// Post step: stops the sidecar, removes the lock and writes the report (scripts/stop.sh). Never fails the job.
const { spawnSync } = require("node:child_process");
const path = require("node:path");

const input = (name) => (process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] || "").trim();
const env = {
  ...process.env,
  EGRESS_SEND_EVENTS: input("send-events") || "off",
  EGRESS_OPENWAF_API: input("openwaf-api") || "https://dash.openwaf.dev",
};
const r = spawnSync("bash", [path.join(__dirname, "scripts", "stop.sh")], { env, stdio: "inherit" });
if (r.status !== 0) {
  console.log(`::warning title=OpenWAF Egress CI::report step exited ${r.status}`);
}
