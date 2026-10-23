// AAC Storage rules tests: AAC doesn't use Storage, so everything is denied.
import { test, before, after } from "node:test";
import { readFileSync } from "node:fs";
import { initializeTestEnvironment, assertFails } from "@firebase/rules-unit-testing";
let env;
const JPEG = "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDA==";
const st = (u) => (u ? env.authenticatedContext(u.uid, { email: u.email }) : env.unauthenticatedContext()).storage();
before(async () => { env = await initializeTestEnvironment({ projectId: "demo-aac", storage: { rules: readFileSync("storage.rules", "utf8") } }); });
after(async () => env.cleanup());
test("DENY member upload", () => assertFails(st({ uid: "alice", email: "alice@x.com" }).ref("profile-photos/alice.jpg").putString(JPEG, "data_url")));
test("DENY admin upload (unused)", () => assertFails(st({ uid: "a", email: "nate@templetonimage.com" }).ref("x.jpg").putString(JPEG, "data_url")));
test("DENY signed-out read", () => assertFails(st(null).ref("x.jpg").getDownloadURL()));
