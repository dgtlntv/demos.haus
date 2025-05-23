import hmac
import os
from hashlib import sha1

import flask
import requests
import yaml
from canonicalwebteam.flask_base.app import FlaskBase
from github3 import login

from webapp.k8s import (
    filter_demos_by_name,
    get_deployment_logs,
    get_deployment_status,
    get_running_demos,
    update_pod_state,
)
from webapp.sso import init_sso, login_required

# Get required values from env or fail
JENKINS_URL = os.environ["JENKINS_URL"]
JENKINS_PUBLIC_URL = os.environ["JENKINS_PUBLIC_URL"]
JENKINS_TOKEN = os.environ["JENKINS_TOKEN"]
GITHUB_ACCESS_TOKEN = os.environ["GITHUB_ACCESS_TOKEN"]
GITHUB_WEBHOOK_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"]

# Create GitHub client
ghub = login(token=GITHUB_ACCESS_TOKEN)

app = FlaskBase(
    __name__,
    "demos.haus",
    template_folder="../templates",
    static_folder="../static",
    template_404="404.html",
    template_500="500.html",
)

init_sso(app)


def get_permanent_demo_config(repo_owner, repo_name):
    """Get permanent demo config for a specific repository"""
    try:
        with open("./permanent-demos.yaml", "r") as f:
            config = yaml.safe_load(f)
            permanent_demos = config.get("permanent_demos", [])
    except FileNotFoundError:
        app.logger.warning("permanent-demos.yaml not found")
        return None
    except yaml.YAMLError as e:
        app.logger.error(f"Error parsing permanent-demos.yaml: {e}")
        return None

    for demo in permanent_demos:
        if demo["repo_owner"] == repo_owner and demo["repo_name"] == repo_name:
            return demo
    return None


def get_jenkins_job(action):
    # To be changed after QA
    return {
        "opened": "webteam/job/start-demo",
        "synchronize": "webteam/job/start-demo",
        "closed": "webteam/job/stop-demo",
    }[action]


def validate_github_webhook_signature(payload, signature):
    """
    Generate the payload signature and compare with the given one
    """
    key = bytes(GITHUB_WEBHOOK_SECRET, "UTF-8")
    hmac_gen = hmac.new(key, payload, sha1)

    # Add append prefix to match the GitHub request format
    digest = f"sha1={hmac_gen.hexdigest()}"

    return hmac.compare_digest(digest, signature)


def handle_webhook_auth_and_ping():
    """Common webhook authentication and ping handling"""
    if not validate_github_webhook_signature(
        flask.request.data, flask.request.headers.get("X-Hub-Signature")
    ):
        return flask.jsonify({"message": "Invalid secret"}, 403)

    # Say hi to github when we do the initial setup.
    if flask.request.headers.get("X-GitHub-Event") == "ping":
        return flask.jsonify({"message": "Hi Github!"}, 200)

    return None


def trigger_jenkins_job(jenkins_job, jenkins_job_params):
    """Common Jenkins job triggering logic"""
    remote_build_url = f"http://{JENKINS_URL}/{jenkins_job}/buildWithParameters?{jenkins_job_params}"
    job_id = ""

    # Trigger the build in jenkins
    if not app.debug:
        response = requests.get(remote_build_url)
        response.raise_for_status()
        # Get the id of the demo
        job_id = response.headers.get("Location").split("/")[-2]
    else:
        # In debug mode just print the URL
        app.logger.info(remote_build_url)
        app.logger.info(job_id)

    return job_id


def extract_payload_info(payload):
    """Extract all relevant information from GitHub webhook payload"""
    return {
        # Common fields
        "repo_owner": payload.get("repository", {})
        .get("owner", {})
        .get("login", ""),
        "repo_name": payload.get("repository", {}).get("name", ""),
        "repo_url": payload.get("repository", {}).get("html_url", ""),
        # PR webhook specific fields
        "action": payload.get("action", ""),
        "pull_request": payload.get("number", ""),
        "pull_request_url": payload.get("pull_request", {}).get(
            "html_url", ""
        ),
        "author": payload.get("sender", {}).get("login", ""),
        "labels": payload.get("pull_request", {}).get("labels", []),
        # Push webhook specific fields
        "ref": payload.get("ref", ""),
    }


@app.route("/")
@login_required
def index():
    return flask.render_template("index.html")


@app.route("/hook/gh", methods=["POST"])
def github_demo_webhook():
    # Handle common authentication and ping
    auth_response = handle_webhook_auth_and_ping()
    if auth_response:
        return auth_response

    payload = flask.request.json
    info = extract_payload_info(payload)

    issue = ghub.issue(
        info["repo_owner"], info["repo_name"], info["pull_request"]
    )
    repo = ghub.repository(info["repo_owner"], info["repo_name"])

    # Only trigger builds if PR author is a collaborator
    allowed_bots = ["renovate[bot]", "dependabot[bot]", "github-actions[bot]"]
    allowed = info["author"] in allowed_bots or repo.is_collaborator(
        info["author"]
    )

    if not allowed:
        message = f"{info['author']} is not a collaborator of the repo"

        # If the PR was opened post the error message
        if info["action"] == "opened":
            issue.create_comment(message)

        return flask.jsonify({"message": message}, 403)

    # Check if the db should be deleted
    keepdb = "false"
    for label in info["labels"]:
        if label["name"] == "keepdb":
            keepdb = "true"
            break

    # Work out the remote build url
    try:
        jenkins_job = get_jenkins_job(info["action"])
    except KeyError:
        return (
            flask.jsonify(
                {"message": f"No job for PR action: {info['action']}"}
            ),
            200,
        )

    jenkins_job_params = f"token={JENKINS_TOKEN}&PR_URL={info['pull_request_url']}&KEEP_DB={keepdb}"

    # Trigger the Jenkins job
    job_id = trigger_jenkins_job(jenkins_job, jenkins_job_params)

    # If the PR was opened post the the link to the demo
    if info["action"] == "opened":
        demo_url = f"https://{info['repo_name'].replace('.', '-')}-{info['pull_request']}.demos.haus"
        jenkins_url = f"{JENKINS_PUBLIC_URL}/{jenkins_job}/{job_id}"

        comment = f"### [<img src='https://assets.ubuntu.com/v1/6baef514-ubuntu-circle-of-friends-large.svg' height=32 width=32> Demo</img>]({demo_url})\n"
        comment += f"### [<img src='https://assets.ubuntu.com/v1/e512b0e2-jenkins.svg' height=32 width=32> Jenkins </img>]({jenkins_url})\n"
        comment += "### [<img src='https://assets.ubuntu.com/v1/7144ec6d-logo-jaas-icon.svg' height=32 width=32> demos.haus </img>](https://demos.haus)\n"

        issue.create_comment(comment)

    return flask.jsonify({"message": "Webhook handled"}, 200)


@app.route("/hook/gh/permanent", methods=["POST"])
def github_permanent_demo_webhook():
    """Handle webhook for permanent main branch demos"""
    # Handle common authentication and ping
    auth_response = handle_webhook_auth_and_ping()
    if auth_response:
        return auth_response

    # Only handle push events to main branch
    if flask.request.headers.get("X-GitHub-Event") != "push":
        return flask.jsonify({"message": "Only push events supported"}, 200)

    payload = flask.request.json
    info = extract_payload_info(payload)

    # Check if this is a push to main branch
    if info["ref"] not in ["refs/heads/main", "refs/heads/master"]:
        return flask.jsonify(
            {"message": "Only main/master branch pushes supported"}, 200
        )

    # Check if this repository has a permanent demo configured
    demo_config = get_permanent_demo_config(
        info["repo_owner"], info["repo_name"]
    )
    if not demo_config:
        return flask.jsonify(
            {
                "message": f"No permanent demo configured for {info['repo_owner']}/{info['repo_name']}"
            },
            200,
        )

    # Get the Jenkins job for permanent demos
    jenkins_job = "webteam/job/start-permanent-demo"

    # Parameters for the permanent demo job
    jenkins_job_params = (
        f"token={JENKINS_TOKEN}&REPO_URL={info['repo_url']}&REPO_OWNER={info['repo_owner']}&"
        f"REPO_NAME={info['repo_name']}&DEMO_URL={demo_config['demo_url']}"
    )

    # Trigger the Jenkins job
    job_id = trigger_jenkins_job(jenkins_job, jenkins_job_params)

    return flask.jsonify(
        {
            "message": f"Permanent demo deployment triggered for {info['repo_owner']}/{info['repo_name']}",
            "demo_url": f"https://{demo_config['demo_url']}",
            "jenkins_job_id": job_id,
        },
        200,
    )


@app.route("/demos", methods=["GET"])
@login_required
def demos():
    return flask.jsonify(get_running_demos())


@app.route("/demo/search")
@login_required
def search():
    query = flask.request.args.get("query")
    demos = get_running_demos()
    if query:
        demos = filter_demos_by_name(demos, query)
    return flask.jsonify(demos)


@app.route("/demo/status", methods=["GET"])
@login_required
def demo_status():
    pod_name = flask.request.args.get("name")
    return flask.jsonify(get_deployment_status(pod_name))


@app.route("/demo/update", methods=["GET"])
@login_required
def update_demo():
    state = flask.request.args.get("state")
    pod_name = flask.request.args.get("name")
    update_pod_state(state, pod_name)
    return flask.jsonify({"message": "Pod state updated", "state": state})


@app.route("/demo/logs/complete", methods=["GET"])
@login_required
def get_logs_page():
    pod_name = flask.request.args.get("name")
    logs = get_deployment_logs(pod_name)
    return flask.render_template("logs.html", logs=logs, name=pod_name)


@app.route("/demo/logs", methods=["GET"])
@login_required
def get_logs():
    pod_name = flask.request.args.get("name")
    logs = get_deployment_logs(pod_name)
    return flask.jsonify({"message": "success", "logs": logs})
