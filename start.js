// Main step: starts the sidecar (scripts/start.sh) with the action inputs. No dependencies on purpose.
const { spawnSync } = require("node:child_process");
const path = require("node:path");

const input = (name) => (process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] || "").trim();
const env = {
  ...process.env,
  EGRESS_POLICY: input("policy") || ".github/egress.yml",
  EGRESS_MODE: input("mode"),
  EGRESS_LOCK: input("lock") || "auto",
  EGRESS_CONTAINERS: input("containers") || "track",
  EGRESS_NO_PROXY: input("no-proxy"),
  EGRESS_GITHUB_TOKEN: input("token"),
};
const r = spawnSync("bash", [path.join(__dirname, "scripts", "start.sh")], { env, stdio: "inherit" });
process.exitCode = r.status === null ? 1 : r.status;
