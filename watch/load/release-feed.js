import http from "k6/http";
import { check } from "k6";

const target = __ENV.TARGET_URL || "https://release-feed.release-feed.svc.cluster.local/healthz";

export const options = {
  scenarios: {
    release_feed_health: {
      executor: "constant-arrival-rate",
      rate: 5,
      timeUnit: "1s",
      duration: "2m",
      preAllocatedVUs: 5,
      maxVUs: 10,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    checks: ["rate>=0.99"],
    http_req_duration: ["p(95)<500"],
  },
};

export default function () {
  const response = http.get(target, { timeout: "2s", tags: { service: "release-feed" } });
  check(response, { "release-feed health is 200": (result) => result.status === 200 });
}
