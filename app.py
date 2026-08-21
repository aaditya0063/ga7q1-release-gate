from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, List, Optional
import re

app = FastAPI()

SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")


@app.post("/release-gate")
def release_gate(data: dict):

    violations = []

    workflow = data["workflow"]
    image = data["image"]

    # Least privilege
    
    perms = workflow.get("permissions", {})

    required = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    if perms != required:
        violations.append("EXCESS_PERMISSION")

    # PR trigger
    
    if data["event"] == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # Tests

    if (
        not workflow.get("testsPassed")
        or not workflow.get("matrixComplete")
        or workflow.get("failFast")
    ):
        violations.append("TESTS_INCOMPLETE")

    # Actions
 
    for action in workflow.get("actions", []):

        if action["owner"] == "actions":
            continue

        if not SHA_PATTERN.fullmatch(action["ref"]):
            violations.append("MUTABLE_ACTION")
            break

    # Image checks

    if not image.get("multiStage"):
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot"):
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if not image.get("digestPinned"):
        violations.append("UNPINNED_IMAGE")

 
    # Production
    
    if data["target"] == "production":

        if not (
            data["event"] == "push"
            and data["ref"] == "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if len(violations) == 0 else "block"

    return {
        "decision": decision,
        "violations": violations,
    }