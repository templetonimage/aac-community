// AAC Firestore rules tests — runs against the Firestore emulator.
// Each "ALLOW" case mirrors a real write/read the app makes; each "DENY" case is an abuse path.
import { test, before, after, beforeEach } from "node:test";
import { readFileSync } from "node:fs";
import { initializeTestEnvironment, assertSucceeds, assertFails } from "@firebase/rules-unit-testing";
import {
  doc, getDoc, setDoc, updateDoc, addDoc, deleteDoc, collection, getDocs, query, where,
  increment, arrayUnion, deleteField,
} from "firebase/firestore";

let env;
const ADMIN = { uid: "adminUid", email: "nate@templetonimage.com" };
const ALICE = { uid: "alice", email: "alice@x.com" };
const BOB = { uid: "bob", email: "bob@x.com" };
const LEGACY = { uid: "legacyAuth", email: "legacy@x.com" };
const db = (u) => (u ? env.authenticatedContext(u.uid, { email: u.email }) : env.unauthenticatedContext()).firestore();
const NOW = Date.now();
const WEEK = Math.floor((NOW - 1782878400000) / 604800000); // roughly the app's current weekIdx
const reply = (uid, ts) => ({ name: uid, uid, text: "nice", timestamp: ts });

before(async () => {
  env = await initializeTestEnvironment({
    projectId: "demo-aac",
    firestore: { rules: readFileSync("firestore.rules", "utf8") },
  });
});
after(async () => { await env.cleanup(); });

beforeEach(async () => {
  await env.clearFirestore();
  await env.withSecurityRulesDisabled(async (ctx) => {
    const f = ctx.firestore();
    await setDoc(doc(f, "aac_registry/alice"), { name: "Alice", email: "alice@x.com", uid: "alice", points: 50, totalPosts: 3,
      isPro: false, subscriptionStatus: "active", preRestrictionStatus: null, stripeCustomerId: "cus_A", allStarStreak: 2, allStarStreakWeekIdx: WEEK - 1 });
    await setDoc(doc(f, "aac_registry/bob"), { name: "Bob", email: "bob@x.com", uid: "bob", points: 20, totalPosts: 1, subscriptionStatus: "trial" });
    await setDoc(doc(f, "aac_registry/locked"), { name: "L", uid: "locked", points: 5, subscriptionStatus: "restricted", preRestrictionStatus: "trial" });
    await setDoc(doc(f, "aac_registry/lockedNoPre"), { name: "L2", uid: "lockedNoPre", points: 5, subscriptionStatus: "restricted", preRestrictionStatus: null });
    await setDoc(doc(f, "aac_registry/cancelled"), { name: "C", uid: "cancelled", points: 5, subscriptionStatus: "cancelled" });
    await setDoc(doc(f, "aac_registry/amb"), { name: "Amb", uid: "amb", points: 40, isAmbassador: true, restartProofAt: 1 });
    await setDoc(doc(f, "aac_registry/bob/campaignBriefs/b1"), { name: "Brief", values: {} });
    await setDoc(doc(f, "posts/postBob"), { author: "Bob", authorUid: "bob", text: "hi", url: "", props: [], propsCount: 0, type: "regular",
      replies: [reply("carol", 1)], timestamp: NOW, weekIdx: WEEK });
    await setDoc(doc(f, "posts/postAliceReplied"), { author: "Bob", authorUid: "bob", text: "x", props: ["Alice"], propsCount: 1, type: "regular",
      replies: [reply("alice", 5), reply("carol", 6)], timestamp: NOW });
    await setDoc(doc(f, "posts/legacyPost"), { author: "Leg", authorUid: "legacy@x.com", text: "old", props: [], propsCount: 0 });
    await setDoc(doc(f, "posts/pvrBob"), { author: "Bob", authorUid: "bob", type: "pvr", pvr_url: "https://ad.example.com", pvr_prompt: "?", replies: [], props: [], propsCount: 0 });
    await setDoc(doc(f, "submissions/subAlice"), { authorUid: "alice", url: "https://ad.example.com", note: "n", pts: 10, weekIdx: WEEK });
    await setDoc(doc(f, "submissions/subBob"), { authorUid: "bob", url: "", pts: 10, weekIdx: WEEK });
    await setDoc(doc(f, "engagements/engAlice"), { authorUid: "alice", pts: 2 });
    await setDoc(doc(f, "trackers/alice"), { uid: "alice" });
    await setDoc(doc(f, "trackers/bob"), { uid: "bob" });
    await setDoc(doc(f, "aac_community_pts/likeAlice"), { uid: "alice", action: "Like", pts: 1, postId: "postBob", ts: NOW });
    await setDoc(doc(f, "aac_community_pts/likeBob"), { uid: "bob", action: "Like", pts: 1, ts: NOW });
    await setDoc(doc(f, "restart_proofs/bob"), { uid: "bob", screenshot: "x" });
    await setDoc(doc(f, "aac_coworking_sessions/s1"), { label: "Cowork", active: true, createdAt: NOW });
    await setDoc(doc(f, "aac_coworking_sessions/_visibility"), { visible: true });
    await setDoc(doc(f, "aac_settings/renewalModal"), { enabled: true, stripeUrl: "https://buy.stripe.com/x" });
    await setDoc(doc(f, "bug_reports/b1"), { uid: "bob", message: "bug", resolved: false });
    await setDoc(doc(f, "announcements/a1"), { title: "T" });
    await setDoc(doc(f, "resources/r1"), { title: "R" });
    await setDoc(doc(f, "expert_reviews/e1"), { uid: "bob" });
    await setDoc(doc(f, "aac_month_archives/2026-10_summary"), { monthKey: "2026-10" });
    await setDoc(doc(f, "aac_private/alice"), { email: "alice@x.com", emailLower: "alice@x.com", stripeCustomerId: "cus_A", stripeSubscriptionId: "sub_A" });
    await setDoc(doc(f, "aac_private/bob"), { email: "bob@x.com", emailLower: "bob@x.com", stripeCustomerId: "cus_B" });
  });
});

// ── Outsiders ────────────────────────────────────────────
test("DENY signed-out read of registry", () => assertFails(getDoc(doc(db(null), "aac_registry/alice"))));
test("DENY signed-out write anywhere", () => assertFails(setDoc(doc(db(null), "posts/x"), { authorUid: "x" })));
test("DENY unknown collection write, even for members", () => assertFails(setDoc(doc(db(ALICE), "evil/x"), { a: 1 })));
test("DENY unknown collection read", () => assertFails(getDoc(doc(db(ALICE), "evil/x"))));

// ── Registry: member paths the app uses ──────────────────
test("ALLOW member reads registry (directory/leaderboard)", () => assertSucceeds(getDocs(collection(db(ALICE), "aac_registry"))));
test("ALLOW lastLogin on boot", () => assertSucceeds(updateDoc(doc(db(ALICE), "aac_registry/alice"), { lastLogin: NOW })));
test("ALLOW feed post +2", () => assertSucceeds(updateDoc(doc(db(ALICE), "aac_registry/alice"), { points: increment(2) })));
test("ALLOW unlike / delete reply -1", () => assertSucceeds(updateDoc(doc(db(ALICE), "aac_registry/alice"), { points: increment(-1) })));
test("ALLOW weekly proof +17 and totalPosts +1", () => assertSucceeds(updateDoc(doc(db(ALICE), "aac_registry/alice"), { points: increment(17), totalPosts: increment(1) })));
test("ALLOW delete own proof -17 and totalPosts -1", () => assertSucceeds(updateDoc(doc(db(ALICE), "aac_registry/alice"), { points: increment(-17), totalPosts: increment(-1) })));
test("ALLOW All-Star bonus +25 with streak fields", () => assertSucceeds(updateDoc(doc(db(ALICE), "aac_registry/alice"),
  { allStarStreak: 4, allStarStreakWeekIdx: WEEK, allStarBadgeUntilWeekIdx: WEEK + 4, points: increment(25) })));
test("ALLOW streak recompute after delete (null week)", () => assertSucceeds(updateDoc(doc(db(ALICE), "aac_registry/alice"), { allStarStreak: 0, allStarStreakWeekIdx: null })));
test("ALLOW profile save", () => assertSucceeds(updateDoc(doc(db(ALICE), "aac_registry/alice"),
  { business: "Biz", type: "Photo", ig: "@a", website: "https://alice.com", photoURL: "data:image/jpeg;base64,AAAA" })));
test("ALLOW profile save with empty website and photo", () => assertSucceeds(updateDoc(doc(db(ALICE), "aac_registry/alice"), { website: "", photoURL: "" })));
test("ALLOW realistic 150KB profile photo", () => assertSucceeds(updateDoc(doc(db(ALICE), "aac_registry/alice"), { photoURL: "data:image/jpeg;base64," + "A".repeat(150000) })));
test("ALLOW audit + buildout + Get Started progress", () => assertSucceeds(updateDoc(doc(db(ALICE), "aac_registry/alice"),
  { auditData: { a: 1 }, buildoutData: {}, activeBriefId: "b1", gsOpenedAt: NOW, gsLastActive: NOW, gsStepsDone: 2, gsTotalSteps: 12, gsPct: 17 })));
test("ALLOW restart modal snooze", () => assertSucceeds(updateDoc(doc(db(ALICE), "aac_registry/alice"), { restartSnoozedUntil: NOW + 1 })));
test("ALLOW Ambassador proof award", () => assertSucceeds(updateDoc(doc(db(BOB), "aac_registry/bob"), { points: increment(25), isAmbassador: true, restartProofAt: NOW })));
test("ALLOW lockout after 2 missed weeks", () => assertSucceeds(updateDoc(doc(db(ALICE), "aac_registry/alice"), { subscriptionStatus: "restricted", preRestrictionStatus: "active" })));
test("ALLOW lockout for a trial member with no status field yet", async () => {
  await env.withSecurityRulesDisabled(c => setDoc(doc(c.firestore(), "aac_registry/bob"), { uid: "bob", points: 1 }));
  await assertSucceeds(updateDoc(doc(db(BOB), "aac_registry/bob"), { subscriptionStatus: "restricted", preRestrictionStatus: "trial" }));
});
test("ALLOW unlock back to the saved status after proof", () => assertSucceeds(updateDoc(doc(db({ uid: "locked", email: "l@x.com" }), "aac_registry/locked"),
  { subscriptionStatus: "trial", preRestrictionStatus: null })));
test("ALLOW unlock to active when no saved status", () => assertSucceeds(updateDoc(doc(db({ uid: "lockedNoPre", email: "l2@x.com" }), "aac_registry/lockedNoPre"),
  { subscriptionStatus: "active", preRestrictionStatus: null })));
test("ALLOW cowork RSVP +2", () => assertSucceeds(updateDoc(doc(db(ALICE), "aac_registry/alice"), { points: increment(2) })));
test("ALLOW member Get Started brief create/read/update/delete", async () => {
  const d = db(BOB);
  const r = await assertSucceeds(addDoc(collection(d, "aac_registry/bob/campaignBriefs"), { name: "New", values: {} }));
  await assertSucceeds(getDocs(collection(d, "aac_registry/bob/campaignBriefs")));
  await assertSucceeds(setDoc(doc(d, "aac_registry/bob/campaignBriefs", r.id), { name: "X" }, { merge: true }));
  await assertSucceeds(deleteDoc(doc(d, "aac_registry/bob/campaignBriefs", r.id)));
});

// ── Registry: abuse ──────────────────────────────────────
test("DENY self-grant Pro", () => assertFails(updateDoc(doc(db(ALICE), "aac_registry/alice"), { isPro: true })));
test("DENY self-set active (skip paying)", () => assertFails(updateDoc(doc(db({ uid: "cancelled", email: "c@x.com" }), "aac_registry/cancelled"), { subscriptionStatus: "active" })));
test("DENY trial member self-set active", () => assertFails(updateDoc(doc(db(BOB), "aac_registry/bob"), { subscriptionStatus: "active" })));
test("DENY lock with a fake saved status (to unlock as active later)", () => assertFails(updateDoc(doc(db(BOB), "aac_registry/bob"), { subscriptionStatus: "restricted", preRestrictionStatus: "active" })));
test("DENY unlock to a different status than saved", () => assertFails(updateDoc(doc(db({ uid: "locked", email: "l@x.com" }), "aac_registry/locked"),
  { subscriptionStatus: "active", preRestrictionStatus: null })));
test("DENY cancelled member locks then unlocks", () => assertFails(updateDoc(doc(db({ uid: "cancelled", email: "c@x.com" }), "aac_registry/cancelled"),
  { subscriptionStatus: "restricted", preRestrictionStatus: "cancelled" })));
test("DENY self-set trial/comp/restart/Stripe fields", async () => {
  const r = doc(db(ALICE), "aac_registry/alice");
  for (const f of [{ trialUntil: NOW * 2 }, { compAccessUntil: NOW * 2 }, { restartedAt: NOW }, { stripeCustomerId: "cus_X" },
    { cancelAtPeriodEnd: false }, { joinWeekIdx: 99 }, { addedAt: NOW }, { proSince: NOW }, { rounds: ["R1"] }])
    await assertFails(updateDoc(r, f));
});
test("DENY self-set Founder/VIP/Expert/manual All-Star/admin", async () => {
  const r = doc(db(ALICE), "aac_registry/alice");
  for (const f of ["isFounder", "isVIP", "isExpert", "isAllStar", "isAdmin"]) await assertFails(updateDoc(r, { [f]: true }));
});
test("DENY rename self (name is admin-only)", () => assertFails(updateDoc(doc(db(ALICE), "aac_registry/alice"), { name: "Nate Templeton" })));
test("DENY change own email/uid", async () => {
  await assertFails(updateDoc(doc(db(ALICE), "aac_registry/alice"), { email: "nate@templetonimage.com" }));
  await assertFails(updateDoc(doc(db(ALICE), "aac_registry/alice"), { uid: "bob" }));
});
test("DENY points jump > 25", () => assertFails(updateDoc(doc(db(ALICE), "aac_registry/alice"), { points: 999 })));
test("DENY points as a string", () => assertFails(updateDoc(doc(db(ALICE), "aac_registry/alice"), { points: "50<img>" })));
test("DENY totalPosts jump", () => assertFails(updateDoc(doc(db(ALICE), "aac_registry/alice"), { totalPosts: 50 })));
test("DENY far-future All-Star badge", () => assertFails(updateDoc(doc(db(ALICE), "aac_registry/alice"), { allStarBadgeUntilWeekIdx: 9999 })));
test("DENY far-future streak week", () => assertFails(updateDoc(doc(db(ALICE), "aac_registry/alice"), { allStarStreakWeekIdx: 9999 })));
test("DENY javascript: website", () => assertFails(updateDoc(doc(db(ALICE), "aac_registry/alice"), { website: "javascript:alert(1)" })));
test("DENY website with quote breakout", () => assertFails(updateDoc(doc(db(ALICE), "aac_registry/alice"), { website: "https://x.com/\" onmouseover=\"alert(1)" })));
test("DENY non-image or SVG photoURL", async () => {
  await assertFails(updateDoc(doc(db(ALICE), "aac_registry/alice"), { photoURL: "x\" onerror=\"alert(1)" }));
  await assertFails(updateDoc(doc(db(ALICE), "aac_registry/alice"), { photoURL: "data:image/svg+xml;base64,AAAA" }));
});
test("DENY Ambassador without proof time / re-flag when already Ambassador", async () => {
  await assertFails(updateDoc(doc(db(BOB), "aac_registry/bob"), { isAmbassador: true }));
  await assertFails(updateDoc(doc(db({ uid: "amb", email: "amb@x.com" }), "aac_registry/amb"), { isAmbassador: true, restartProofAt: NOW, points: increment(25) }));
});
test("DENY edit someone else's registry doc", () => assertFails(updateDoc(doc(db(ALICE), "aac_registry/bob"), { points: increment(-1) })));
test("DENY member creates or deletes a registry doc", async () => {
  await assertFails(setDoc(doc(db(ALICE), "aac_registry/fake"), { name: "Fake" }));
  await assertFails(deleteDoc(doc(db(ALICE), "aac_registry/alice")));
});
test("DENY reading someone else's campaign briefs", () => assertFails(getDocs(collection(db(ALICE), "aac_registry/bob/campaignBriefs"))));

// ── Feed ─────────────────────────────────────────────────
const newPost = (uid, extra = {}) => ({ author: uid, authorUid: uid, text: "hi", url: "", props: [], propsCount: 0, timestamp: NOW, weekIdx: WEEK, type: "regular", ...extra });
test("ALLOW member creates feed post", () => assertSucceeds(addDoc(collection(db(ALICE), "posts"), newPost("alice", { url: "https://alice.com/x" }))));
test("ALLOW member creates peer review request", () => assertSucceeds(addDoc(collection(db(ALICE), "posts"),
  { author: "A", authorUid: "alice", type: "pvr", pvr_url: "https://ad.example.com", pvr_prompt: "?", weekIdx: WEEK, replies: [], props: [], propsCount: 0, timestamp: NOW })));
test("ALLOW member likes someone else's post", () => assertSucceeds(updateDoc(doc(db(ALICE), "posts/postBob"), { props: ["Alice"], propsCount: 1 })));
test("ALLOW member unlikes", () => assertSucceeds(updateDoc(doc(db(ALICE), "posts/postAliceReplied"), { props: [], propsCount: 0 })));
test("ALLOW member replies to someone else's post (arrayUnion)", () => assertSucceeds(updateDoc(doc(db(ALICE), "posts/postBob"), { replies: arrayUnion(reply("alice", 9)) })));
test("ALLOW peer review feedback reply", () => assertSucceeds(updateDoc(doc(db(ALICE), "posts/pvrBob"), { replies: arrayUnion(reply("alice", 10)) })));
test("ALLOW member deletes own reply on someone else's post", () => assertSucceeds(updateDoc(doc(db(ALICE), "posts/postAliceReplied"), { replies: [reply("carol", 6)] })));
test("ALLOW author edits own post text/url", () => assertSucceeds(updateDoc(doc(db(BOB), "posts/postBob"), { text: "edited", url: "https://bob.com" })));
test("ALLOW author edits peer review prompt", () => assertSucceeds(updateDoc(doc(db(BOB), "posts/pvrBob"), { pvr_prompt: "new?" })));
test("ALLOW author deletes own post", () => assertSucceeds(deleteDoc(doc(db(BOB), "posts/postBob"))));
test("ALLOW legacy post owned by email", () => assertSucceeds(updateDoc(doc(db(LEGACY), "posts/legacyPost"), { text: "edit" })));
test("DENY post as someone else", () => assertFails(addDoc(collection(db(ALICE), "posts"), newPost("bob"))));
test("DENY post with pre-filled props/replies", async () => {
  await assertFails(addDoc(collection(db(ALICE), "posts"), newPost("alice", { props: ["x", "y"], propsCount: 2 })));
  await assertFails(addDoc(collection(db(ALICE), "posts"), newPost("alice", { replies: [reply("bob", 1)] })));
});
test("DENY post with javascript: link", () => assertFails(addDoc(collection(db(ALICE), "posts"), newPost("alice", { url: "javascript:alert(1)" }))));
test("DENY post type expert-response by member", () => assertFails(addDoc(collection(db(ALICE), "posts"), newPost("alice", { type: "expert-response" }))));
test("DENY editing someone else's post text", () => assertFails(updateDoc(doc(db(ALICE), "posts/postBob"), { text: "hacked" })));
test("DENY author edit to javascript: link", () => assertFails(updateDoc(doc(db(BOB), "posts/postBob"), { url: "javascript:alert(1)" })));
test("DENY deleting someone else's post", () => assertFails(deleteDoc(doc(db(ALICE), "posts/postBob"))));
test("DENY removing someone else's reply", () => assertFails(updateDoc(doc(db(ALICE), "posts/postBob"), { replies: [] })));
test("DENY replying as someone else", () => assertFails(updateDoc(doc(db(ALICE), "posts/postBob"), { replies: arrayUnion(reply("bob", 11)) })));
test("DENY props count that doesn't match / mass props", async () => {
  await assertFails(updateDoc(doc(db(ALICE), "posts/postBob"), { props: ["A"], propsCount: 50 }));
  await assertFails(updateDoc(doc(db(ALICE), "posts/postBob"), { props: ["A", "B", "C"], propsCount: 3 }));
});
test("DENY props change bundled with text change", () => assertFails(updateDoc(doc(db(ALICE), "posts/postBob"), { props: ["A"], propsCount: 1, text: "x" })));

// ── Proof submissions & engagements ──────────────────────
const sub = (uid, extra = {}) => ({ author: uid, authorUid: uid, weekIdx: WEEK, weekLabel: "Oct 22–31", url: "https://ad.example.com", note: "", format: "Campaign Proof",
  challengeCompleted: true, hasScreenshot: true, pts: 17, isLate: false, timestamp: NOW, ...extra });
test("ALLOW weekly proof (17 pts max)", () => assertSucceeds(addDoc(collection(db(ALICE), "submissions"), sub("alice"))));
test("ALLOW proof without URL", () => assertSucceeds(addDoc(collection(db(ALICE), "submissions"), sub("alice", { url: "", pts: 10 }))));
test("ALLOW member edits own proof url/note", () => assertSucceeds(updateDoc(doc(db(ALICE), "submissions/subAlice"), { url: "https://new.example.com", note: "x", editedAt: NOW })));
test("ALLOW member deletes own proof", () => assertSucceeds(deleteDoc(doc(db(ALICE), "submissions/subAlice"))));
test("ALLOW queries used by dashboard/leaderboard", async () => {
  await assertSucceeds(getDocs(query(collection(db(ALICE), "submissions"), where("timestamp", ">=", 0))));
  await assertSucceeds(getDocs(query(collection(db(ALICE), "aac_community_pts"), where("ts", ">=", 0))));
});
test("DENY proof with inflated points", () => assertFails(addDoc(collection(db(ALICE), "submissions"), sub("alice", { pts: 500 }))));
test("DENY proof as someone else", () => assertFails(addDoc(collection(db(ALICE), "submissions"), sub("bob"))));
test("DENY proof with javascript: link", () => assertFails(addDoc(collection(db(ALICE), "submissions"), sub("alice", { url: "javascript:alert(1)" }))));
test("DENY member raises pts on own proof", () => assertFails(updateDoc(doc(db(ALICE), "submissions/subAlice"), { pts: 17 })));
test("DENY editing/deleting someone else's proof", async () => {
  await assertFails(updateDoc(doc(db(ALICE), "submissions/subBob"), { note: "x" }));
  await assertFails(deleteDoc(doc(db(ALICE), "submissions/subBob")));
});
test("ALLOW peer review feedback engagement (+2)", () => assertSucceeds(addDoc(collection(db(ALICE), "engagements"),
  { author: "A", authorUid: "alice", weekIdx: WEEK, targetUrl: "", note: "x", type: "PVR Feedback", hasScreenshot: false, pts: 2, isPVR: true, timestamp: NOW })));
test("DENY engagement with inflated pts / for someone else", async () => {
  await assertFails(addDoc(collection(db(ALICE), "engagements"), { authorUid: "alice", pts: 50 }));
  await assertFails(addDoc(collection(db(ALICE), "engagements"), { authorUid: "bob", pts: 2 }));
});
test("ALLOW own tracker read/write", async () => {
  await assertSucceeds(getDoc(doc(db(ALICE), "trackers/alice")));
  await assertSucceeds(setDoc(doc(db(ALICE), "trackers/alice"), { "trial.t1": [true], uid: "alice" }, { merge: true }));
});
test("DENY someone else's tracker", async () => {
  await assertFails(getDoc(doc(db(ALICE), "trackers/bob")));
  await assertFails(setDoc(doc(db(ALICE), "trackers/bob"), { uid: "bob" }, { merge: true }));
});

// ── Community points ledger ──────────────────────────────
test("ALLOW member logs own feed post / like / reply / peer review / RSVP", async () => {
  const c = collection(db(ALICE), "aac_community_pts");
  await assertSucceeds(addDoc(c, { uid: "alice", name: "A", action: "Feed Post", pts: 2, ts: NOW, postId: "p" }));
  await assertSucceeds(addDoc(c, { uid: "alice", name: "A", action: "Like", pts: 1, ts: NOW, postId: "p" }));
  await assertSucceeds(addDoc(c, { uid: "alice", name: "A", action: "Reply", pts: 1, ts: NOW, postId: "p", replyTs: 1 }));
  await assertSucceeds(addDoc(c, { uid: "alice", name: "A", action: "Peer Review Request", pts: 5, ts: NOW }));
  await assertSucceeds(addDoc(c, { uid: "alice", name: "A", action: "Session RSVP", pts: 2, ts: NOW }));
});
test("ALLOW Ambassador ledger entry (fixed id, 25)", () => assertSucceeds(setDoc(doc(db(BOB), "aac_community_pts/restart_ambassador_bob"),
  { uid: "bob", name: "B", action: "Restart Ambassador", type: "restart_ambassador", pts: 25, ts: NOW })));
test("ALLOW member deletes own like log (unlike)", () => assertSucceeds(deleteDoc(doc(db(ALICE), "aac_community_pts/likeAlice"))));
test("DENY ledger entry for someone else", () => assertFails(addDoc(collection(db(ALICE), "aac_community_pts"), { uid: "bob", action: "Like", pts: 1, ts: NOW })));
test("DENY ledger entry with big or string pts", async () => {
  await assertFails(addDoc(collection(db(ALICE), "aac_community_pts"), { uid: "alice", action: "Like", pts: 500, ts: NOW }));
  await assertFails(addDoc(collection(db(ALICE), "aac_community_pts"), { uid: "alice", action: "Like", pts: "1);alert(1)//", ts: NOW }));
});
test("DENY member fakes a Restart (+10) or extra Ambassador entry", async () => {
  await assertFails(addDoc(collection(db(ALICE), "aac_community_pts"), { uid: "alice", action: "Restart", type: "restart", pts: 5, ts: NOW }));
  await assertFails(setDoc(doc(db(ALICE), "aac_community_pts/extra"), { uid: "alice", type: "restart_ambassador", pts: 25, ts: NOW }));
});
test("DENY deleting someone else's ledger entry / editing any", async () => {
  await assertFails(deleteDoc(doc(db(ALICE), "aac_community_pts/likeBob")));
  await assertFails(updateDoc(doc(db(ALICE), "aac_community_pts/likeAlice"), { pts: 5 }));
});

// ── Ambassador proof ─────────────────────────────────────
test("ALLOW member submits/resubmits own proof", async () => {
  await assertSucceeds(setDoc(doc(db(ALICE), "restart_proofs/alice"), { uid: "alice", name: "A", type: "restart_ambassador", screenshot: "data:image/jpeg;base64,AA", createdAt: NOW }));
  await assertSucceeds(setDoc(doc(db(ALICE), "restart_proofs/alice"), { uid: "alice", screenshot: "y", updatedAt: NOW }, { merge: true }));
});
test("DENY reading or writing someone else's proof", async () => {
  await assertFails(getDoc(doc(db(ALICE), "restart_proofs/bob")));
  await assertFails(setDoc(doc(db(ALICE), "restart_proofs/bob"), { uid: "bob" }));
});

// ── Coworking ────────────────────────────────────────────
test("ALLOW member reads sessions, visibility switch, own RSVP", async () => {
  await assertSucceeds(getDocs(query(collection(db(ALICE), "aac_coworking_sessions"), where("active", "==", true))));
  await assertSucceeds(getDoc(doc(db(ALICE), "aac_coworking_sessions/_visibility")));
  await assertSucceeds(getDoc(doc(db(ALICE), "aac_coworking_sessions/s1/rsvps/alice")));
  await assertSucceeds(setDoc(doc(db(ALICE), "aac_coworking_sessions/s1/rsvps/alice"), { uid: "alice", name: "A", rsvpAt: NOW }));
});
test("DENY member RSVPs as someone else / marks attendance / edits session", async () => {
  await assertFails(setDoc(doc(db(ALICE), "aac_coworking_sessions/s1/rsvps/bob"), { uid: "bob" }));
  await assertFails(setDoc(doc(db(ALICE), "aac_coworking_sessions/s1/attendees/alice"), { uid: "alice" }));
  await assertFails(updateDoc(doc(db(ALICE), "aac_coworking_sessions/s1"), { calendarUrl: "https://evil.example.com" }));
  await assertFails(setDoc(doc(db(ALICE), "aac_coworking_sessions/_visibility"), { visible: false }));
});

// ── Reports, config, admin-only ──────────────────────────
test("ALLOW member files a bug report and logs an error", async () => {
  await assertSucceeds(addDoc(collection(db(ALICE), "bug_reports"), { name: "A", email: "alice@x.com", uid: "alice", message: "m", screenshot: null, resolved: false, ts: NOW }));
  await assertSucceeds(addDoc(collection(db(ALICE), "platform_errors"), { context: "x", message: "y", timestamp: NOW }));
});
test("DENY member reads bug reports / files as someone else", async () => {
  await assertFails(getDoc(doc(db(ALICE), "bug_reports/b1")));
  await assertFails(addDoc(collection(db(ALICE), "bug_reports"), { uid: "bob", message: "m", resolved: false }));
});
test("ALLOW member reads announcements, resources, renewal config", async () => {
  await assertSucceeds(getDocs(collection(db(ALICE), "announcements")));
  await assertSucceeds(getDocs(collection(db(ALICE), "resources")));
  await assertSucceeds(getDoc(doc(db(ALICE), "aac_settings/renewalModal")));
});
test("DENY member writes announcements, resources, renewal config (Stripe link)", async () => {
  await assertFails(addDoc(collection(db(ALICE), "announcements"), { title: "fake" }));
  await assertFails(updateDoc(doc(db(ALICE), "resources/r1"), { url: "https://evil.example.com" }));
  await assertFails(setDoc(doc(db(ALICE), "aac_settings/renewalModal"), { stripeUrl: "https://evil.example.com" }));
});
test("DENY member sends email via mail collection", () => assertFails(addDoc(collection(db(ALICE), "mail"), { to: "x@y.com", message: { subject: "s", html: "h" } })));
test("DENY member touches expert_reviews or month archives", async () => {
  await assertFails(getDoc(doc(db(ALICE), "expert_reviews/e1")));
  await assertFails(addDoc(collection(db(ALICE), "expert_reviews"), { a: 1 }));
  await assertFails(getDoc(doc(db(ALICE), "aac_month_archives/2026-10_summary")));
  await assertFails(setDoc(doc(db(ALICE), "aac_month_archives/x"), { a: 1 }));
});

// ── Admin paths the app uses ─────────────────────────────
test("ALLOW admin registry tools (status, flags, Pro, trial, email, points, create, delete)", async () => {
  const d = db(ADMIN);
  await assertSucceeds(updateDoc(doc(d, "aac_registry/alice"), { subscriptionStatus: "cancelled", preRestrictionStatus: null }));
  await assertSucceeds(updateDoc(doc(d, "aac_registry/alice"), { isFounder: true, isPro: true, proSince: NOW, trialUntil: NOW }));
  await assertSucceeds(updateDoc(doc(d, "aac_registry/alice"), { email: "new@x.com", points: 0, totalPosts: 0 }));
  await assertSucceeds(updateDoc(doc(d, "aac_registry/alice"), { isAmbassador: false, restartProofAt: null, points: increment(-25) }));
  await assertSucceeds(setDoc(doc(d, "aac_registry/newUid"), { name: "New", uid: "newUid", points: 0, subscriptionStatus: "trial" }));
  await assertSucceeds(deleteDoc(doc(d, "aac_registry/bob")));
});
test("ALLOW admin feed + content moderation", async () => {
  const d = db(ADMIN);
  await assertSucceeds(updateDoc(doc(d, "posts/postBob"), { replies: arrayUnion({ name: "Nate", uid: "adminUid", text: "c", isAdminComment: true, timestamp: NOW }) }));
  await assertSucceeds(updateDoc(doc(d, "posts/postAliceReplied"), { replies: [] }));
  await assertSucceeds(deleteDoc(doc(d, "posts/postBob")));
  await assertSucceeds(addDoc(collection(d, "announcements"), { title: "T", body: "B", timestamp: NOW }));
  await assertSucceeds(updateDoc(doc(d, "announcements/a1"), { archived: true }));
  await assertSucceeds(addDoc(collection(d, "resources"), { title: "R" }));
  await assertSucceeds(setDoc(doc(d, "aac_settings/renewalModal"), { enabled: false }));
});
test("ALLOW admin points tools, ledger edits, submissions editor", async () => {
  const d = db(ADMIN);
  await assertSucceeds(updateDoc(doc(d, "aac_registry/bob"), { points: increment(500) }));
  await assertSucceeds(setDoc(doc(d, "aac_community_pts/restart_bob"), { uid: "bob", type: "restart", pts: 10, ts: NOW, bulkAward: true }));
  await assertSucceeds(updateDoc(doc(d, "aac_community_pts/likeBob"), { action: "Like", pts: 2 }));
  await assertSucceeds(deleteDoc(doc(d, "aac_community_pts/likeBob")));
  await assertSucceeds(updateDoc(doc(d, "submissions/subBob"), { pts: 12, note: "fixed" }));
  await assertSucceeds(deleteDoc(doc(d, "submissions/subBob")));
  await assertSucceeds(deleteDoc(doc(d, "restart_proofs/bob")));
  await assertSucceeds(getDocs(collection(d, "aac_registry/bob/campaignBriefs")));
});
test("ALLOW admin coworking, bug reports, archives, mail", async () => {
  const d = db(ADMIN);
  await assertSucceeds(addDoc(collection(d, "aac_coworking_sessions"), { label: "L", calendarUrl: "", active: true, createdAt: NOW }));
  await assertSucceeds(setDoc(doc(d, "aac_coworking_sessions/_visibility"), { visible: false }));
  await assertSucceeds(setDoc(doc(d, "aac_coworking_sessions/s1/attendees/alice"), { uid: "alice", awardedAt: NOW }));
  await assertSucceeds(getDocs(collection(d, "bug_reports")));
  await assertSucceeds(updateDoc(doc(d, "bug_reports/b1"), { resolved: true }));
  await assertSucceeds(deleteDoc(doc(d, "bug_reports/b1")));
  await assertSucceeds(setDoc(doc(d, "aac_month_archives/2026-10_alice"), { monthKey: "2026-10" }));
  await assertSucceeds(addDoc(collection(d, "mail"), { to: "a@b.com" }));
});

// ── Private member fields (Stage 2b) ─────────────────────
test("ALLOW member reads own private doc (billing card)", () => assertSucceeds(getDoc(doc(db(ALICE), "aac_private/alice"))));
test("ALLOW member reads own private doc even if it doesn't exist yet", () => assertSucceeds(getDoc(doc(db({ uid: "newbie", email: "n@x.com" }), "aac_private/newbie"))));
test("DENY member reads someone else's private doc", () => assertFails(getDoc(doc(db(ALICE), "aac_private/bob"))));
test("DENY member lists private docs", () => assertFails(getDocs(collection(db(ALICE), "aac_private"))));
test("DENY member writes own private doc (Stripe IDs are server-set)", async () => {
  await assertFails(updateDoc(doc(db(ALICE), "aac_private/alice"), { stripeCustomerId: "cus_X" }));
  await assertFails(setDoc(doc(db({ uid: "newbie", email: "n@x.com" }), "aac_private/newbie"), { email: "n@x.com" }));
});
test("DENY signed-out read of private docs", () => assertFails(getDoc(doc(db(null), "aac_private/alice"))));
test("ALLOW admin lists private docs, edits email, runs migration (copy + delete registry fields)", async () => {
  const d = db(ADMIN);
  await assertSucceeds(getDocs(collection(d, "aac_private")));
  await assertSucceeds(setDoc(doc(d, "aac_private/alice"), { email: "new@x.com", emailLower: "new@x.com", updatedAt: NOW }, { merge: true }));
  await assertSucceeds(setDoc(doc(d, "aac_private/carol"), { email: "c@x.com", emailLower: "c@x.com", stripeCustomerId: null, stripeSubscriptionId: null, updatedAt: NOW }, { merge: true }));
  await assertSucceeds(updateDoc(doc(d, "aac_registry/alice"), { email: deleteField(), stripeCustomerId: deleteField() }));
});
test("DENY member re-adding email/Stripe fields to the registry", async () => {
  await assertFails(updateDoc(doc(db(ALICE), "aac_registry/alice"), { stripeCustomerId: "cus_X" }));
  await assertFails(updateDoc(doc(db(ALICE), "aac_registry/alice"), { email: "x@x.com" }));
});
