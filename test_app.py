from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_safe_payload():

    payload = {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/dev",

        "workflow":{

            "trigger":"pull_request",

            "permissions":{

                "contents":"read",
                "packages":"write",
                "id-token":"none"

            },

            "testsPassed":True,
            "matrixComplete":True,
            "failFast":False,

            "actions":[
                {
                    "owner":"actions",
                    "name":"checkout",
                    "ref":"v4"
                }
            ]
        },

        "image":{

            "multiStage":True,
            "runsAsRoot":False,
            "secretMode":"none",
            "criticalVulnerabilities":0,
            "digestPinned":True

        }
    }

    r = client.post("/release-gate", json=payload)

    assert r.status_code == 200
    assert r.json()["decision"] == "promote"