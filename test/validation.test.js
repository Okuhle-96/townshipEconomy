process.env.DATABASE_URL ||= "postgresql://test:test@localhost:5432/township_test";
process.env.SESSION_SECRET ||= "unit-test-session-secret-with-more-than-32-characters";

const test = require("node:test");
const assert = require("node:assert/strict");
const { parseListingKind, validateListing, validatePassword, sendPasswordResetEmail } = require("../server");

test("enforces the password length and byte limits", () => {
  assert.equal(validatePassword("correct horse battery"), "correct horse battery");
  assert.throws(() => validatePassword("short"), /at least 12 characters/);
  assert.throws(() => validatePassword("😀".repeat(19)), /maximum 72 bytes/);
});

test("sends reset links through Resend using the configured site origin", async t => {
  const originalEnvironment = {
    APP_ORIGIN: process.env.APP_ORIGIN,
    RESEND_API_KEY: process.env.RESEND_API_KEY,
    RESEND_FROM_EMAIL: process.env.RESEND_FROM_EMAIL
  };
  const originalFetch = global.fetch;
  t.after(() => {
    for (const [key, value] of Object.entries(originalEnvironment)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    global.fetch = originalFetch;
  });

  const token = "A".repeat(43);
  process.env.APP_ORIGIN = "https://township.example";
  process.env.RESEND_API_KEY = "test-resend-key";
  process.env.RESEND_FROM_EMAIL = "Township Economy <hello@township.example>";
  global.fetch = async (url, options) => {
    assert.equal(url, "https://api.resend.com/emails");
    assert.equal(options.headers.Authorization, "Bearer test-resend-key");
    const email = JSON.parse(options.body);
    assert.equal(email.from, process.env.RESEND_FROM_EMAIL);
    assert.deepEqual(email.to, ["member@township.example"]);
    assert.match(email.text, new RegExp(`https://township\\.example/\\?reset=${token}`));
    return { ok: true, status: 200 };
  };

  await sendPasswordResetEmail("member@township.example", token);
});

test("rejects non-origin reset URLs before sending email", async t => {
  const originalEnvironment = {
    APP_ORIGIN: process.env.APP_ORIGIN,
    RESEND_API_KEY: process.env.RESEND_API_KEY,
    RESEND_FROM_EMAIL: process.env.RESEND_FROM_EMAIL
  };
  const originalFetch = global.fetch;
  t.after(() => {
    for (const [key, value] of Object.entries(originalEnvironment)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    global.fetch = originalFetch;
  });

  process.env.APP_ORIGIN = "javascript:alert(1)";
  process.env.RESEND_API_KEY = "test-resend-key";
  process.env.RESEND_FROM_EMAIL = "Township Economy <hello@township.example>";
  global.fetch = () => {
    throw new Error("Email should not be sent for an invalid origin.");
  };

  await assert.rejects(sendPasswordResetEmail("member@township.example", "A".repeat(43)), /exact http or https origin/);
});

test("validates community member profiles", () => {
  const member = validateListing("members", {
    name: "  A Member  ",
    role: "Builder",
    location: "Central",
    about: "",
    tags: ["Repairs"]
  });
  assert.equal(member.name, "A Member");
  assert.deepEqual(member.tags, ["Repairs"]);
});

test("validates hiring and job-seeking listings and optional contact links", () => {
  const job = validateListing("jobs", {
    title: "Shop assistant",
    company: "Local shop",
    type: "Seeking work",
    location: "Eastside",
    description: "Available weekdays",
    contact: "person@example.com",
    whatsapp: "+27 82 123 4567",
    instagram: "https://instagram.com/local"
  });
  assert.equal(job.type, "Seeking work");
  assert.equal(job.instagram, "https://instagram.com/local");
  assert.equal(job.facebook, "");
});

test("rejects unsafe social links, invalid WhatsApp numbers, and unsupported listing types", () => {
  assert.throws(() => validateListing("services", {
    name: "Provider",
    category: "Repairs",
    location: "Central",
    description: "Home repairs",
    contact: "provider@example.com",
    website: "javascript:alert(1)"
  }), /valid http or https URL/);

  assert.throws(() => validateListing("jobs", {
    title: "Role",
    company: "Employer",
    type: "Unknown",
    location: "Central",
    description: "Details",
    contact: "person@example.com"
  }), /Choose Hiring or Seeking work/);

  assert.throws(() => parseListingKind("unknown"), /valid listing category/);
});
