#!/usr/bin/env python3
"""Validate generated CRDs and the provider in a disposable Kind cluster."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(*args, timeout=120, **kwargs):
    return subprocess.run(args, cwd=ROOT, timeout=timeout, check=True, **kwargs)


def main():
    with tempfile.TemporaryDirectory(prefix="oauthrelay-kubernetes-") as directory:
        config = str(Path(directory) / "kubeconfig")
        name = f"oauthrelay-test-{os.getpid()}"
        try:
            run("kind", "create", "cluster", "--name", name, "--image", "kindest/node:v1.35.0",
                "--kubeconfig", config, "--wait", "120s", timeout=300)
            kubectl = ["kubectl", "--kubeconfig", config, "--request-timeout=30s"]
            run(*kubectl, "apply", "--server-side", "-f", "deploy/oauthrelay.crds.yaml")
            run(*kubectl, "wait", "--for=condition=Established", "--timeout=60s",
                "crd/upstreams.oauthrelay.dev", "crd/relays.oauthrelay.dev")
            env = dict(os.environ, RUSTC_WRAPPER="", OAUTHRELAY_KUBERNETES_TEST_KUBECONFIG=config)
            run("cargo", "test", "--locked", "-p", "oauthrelay-provider-kubernetes",
                "--test", "kubernetes", "--", "--ignored", "--nocapture", timeout=600, env=env)
        finally:
            run("kind", "delete", "cluster", "--name", name, timeout=120)


if __name__ == "__main__":
    main()
