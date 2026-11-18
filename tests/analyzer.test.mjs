import test from "node:test";
import assert from "node:assert/strict";
import {analyzeUrl} from "../analyzer.js";

test("requires a complete HTTP or HTTPS URL",()=>{assert.throws(()=>analyzeUrl("example.test"),/complete URL/);assert.throws(()=>analyzeUrl("ftp://example.test"),/Only HTTP/);});
test("does not treat declared HTTPS as certificate verification",()=>{const r=analyzeUrl("https://accounts.example.test/login");assert.equal(r.scheme,"HTTPS");assert.match(r.verifiedStatement,/No DNS, certificate/);});
test("flags misleading brand subdomains",()=>{const r=analyzeUrl("http://paypal.com.security-check.example.test/sign-in");assert.ok(r.score>=70);assert.ok(r.findings.some(f=>f.title.includes("brand impersonation")));});
test("flags punycode without decoding or visiting",()=>{const r=analyzeUrl("https://xn--pple-43d.example.test/verify");assert.ok(r.findings.some(f=>f.title.includes("Punycode")));});
test("flags embedded credentials and reports the actual host",()=>{const r=analyzeUrl("https://trusted.example@destination.example.test/login");const finding=r.findings.find(f=>f.title.includes("Credentials"));assert.equal(finding.evidence,"Actual host: destination.example.test");});
test("flags unexpected download-like paths",()=>{const r=analyzeUrl("https://files.example.test/update.exe");assert.ok(r.findings.some(f=>f.title.includes("Executable")));});
test("caps risk at one hundred",()=>{const r=analyzeUrl("http://paypal:secret@192.0.2.1:8080/update.exe?x=%41%42%43%44");assert.equal(r.score,100);});
