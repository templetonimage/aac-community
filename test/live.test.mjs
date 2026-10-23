// Confirms current LIVE behavior (not the new rules): what members can and can't do today.
import { test, before, after } from "node:test";
import { readFileSync } from "node:fs";
import { initializeTestEnvironment, assertSucceeds, assertFails } from "@firebase/rules-unit-testing";
import { doc, setDoc, updateDoc, arrayUnion } from "firebase/firestore";
let env;
before(async () => {
  env = await initializeTestEnvironment({ projectId: "demo-aac-live", firestore: { rules: readFileSync("live.rules", "utf8") } });
  await env.withSecurityRulesDisabled(async c => {
    await setDoc(doc(c.firestore(), "posts/p"), { authorUid: "bob", props: [], propsCount: 0, replies: [] });
    await setDoc(doc(c.firestore(), "aac_registry/alice"), { uid: "alice", isPro: false, points: 1 });
  });
});
after(async () => env.cleanup());
let _alice; const alice = () => (_alice ??= env.authenticatedContext("alice", { email: "alice@x.com" }).firestore());
test("LIVE today: member like on another's post is BLOCKED", () => assertFails(updateDoc(doc(alice(), "posts/p"), { props: ["Alice"], propsCount: 1 })));
test("LIVE today: member reply on another's post is BLOCKED", () => assertFails(updateDoc(doc(alice(), "posts/p"), { replies: arrayUnion({ uid: "alice", text: "x" }) })));
test("LIVE today: member CAN self-grant Pro and points", () => assertSucceeds(updateDoc(doc(alice(), "aac_registry/alice"), { isPro: true, points: 99999, subscriptionStatus: "active" })));
