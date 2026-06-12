# TaskBoard — Prioritized Issues

**Prioritized by Business Impact** | Last Updated: 2026-06-12

---

## 🔴 CRITICAL — Data Compromise / Security Breach Risk

### 1. SQL Injection Vulnerability in Task Search
**Category:** Security | **Severity:** CRITICAL  
**File:** [src/app/api/projects/[id]/tasks/route.ts](src/app/api/projects/[id]/tasks/route.ts#L18-L25)

The search endpoint constructs raw SQL using string concatenation with user input, allowing attackers to execute arbitrary SQL queries. This grants complete database access including user passwords and sensitive project data. **Requires immediate fix using parameterized queries or Prisma query builder.**

**Proof of Concept:**
```bash
# Normal search (safe)
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:3000/api/projects/PROJECT_ID/tasks?q=test"

# SQL Injection payload (demonstrates vulnerability)
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:3000/api/projects/PROJECT_ID/tasks?q='; DROP TABLE tasks; --"

# Another example: Extract all data
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:3000/api/projects/PROJECT_ID/tasks?q=%' OR '1'='1"
```

---

### 2. Missing Authorization Check on Task PATCH Endpoint
**Category:** Security | **Severity:** CRITICAL  
**File:** [src/app/api/tasks/[id]/route.ts](src/app/api/tasks/[id]/route.ts#L7-L25)

The PATCH endpoint updates tasks without verifying the user is a project member, while the DELETE endpoint correctly enforces this check. An authenticated user can modify any task in the database regardless of project membership. **DELETE endpoint has the correct pattern at lines 28-40; apply same logic to PATCH.**

**Proof of Concept:**
```bash
# 1. Login as "dev@example.com" (viewer on Q3 Launch only)
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"dev@example.com","password":"password123"}' | jq -r '.token'

# Save token: export TOKEN="<token_from_above>"

# 2. Get a task ID from a project you're NOT a member of
curl -H "Authorization: Bearer OTHER_USER_TOKEN" \
  "http://localhost:3000/api/projects/DIFFERENT_PROJECT_ID/tasks" | jq -r '.tasks[0].id'

# Save task ID: export TASK_ID="<task_id>"

# 3. Now exploit: Update that task even though you're not in the project
curl -X PATCH http://localhost:3000/api/tasks/$TASK_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"HACKED - This task was updated by unauthorized user","status":"done"}'

# Expected: 403 Forbidden (but currently returns 200 OK - the bug!)
```

---

## 🟠 HIGH — Data Loss / Recovery Impossible

### 3. Hard Deletes Only — No Soft Deletes or Audit Trail
**Category:** Data Integrity | **Severity:** HIGH  
**File:** [src/app/api/projects/[id]/route.ts](src/app/api/projects/[id]/route.ts#L74-L75) (and cascade in other delete endpoints)

Projects and tasks are permanently deleted from the database with no recovery option or audit trail. Users cannot recover accidentally deleted work, and compliance/forensic requirements cannot be met. **Add `deletedAt` soft-delete timestamps to Project and Task models; implement logical deletes instead.**

**Proof of Concept:**
```bash
# 1. Get a project ID
export TOKEN="<your_admin_token>"
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:3000/api/projects" | jq -r '.projects[0].id'

# Save project ID
export PROJECT_ID="<project_id>"

# 2. Delete the project (permanently removes from DB - no recovery!)
curl -X DELETE http://localhost:3000/api/projects/$PROJECT_ID \
  -H "Authorization: Bearer $TOKEN"

# 3. Try to retrieve it - gone forever
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:3000/api/projects/$PROJECT_ID"
# Returns: 403 or 404 (data is lost, no way to restore)

# If soft deletes were implemented, you could query deleted records:
# SELECT * FROM projects WHERE "deletedAt" IS NOT NULL;
```

---

## 🟠 HIGH — Performance Degradation at Scale

### 4. N+1 Query Problem in Projects List
**Category:** Performance | **Severity:** HIGH  
**File:** [src/app/api/projects/route.ts](src/app/api/projects/route.ts#L10-16)

For each project membership, the endpoint fetches and includes ALL tasks just to count them (via `taskCount: m.project.tasks.length`). With 100 projects and 1000 tasks each, this causes 100+ unnecessary full task fetches. **Use Prisma `_count` relation or raw COUNT() query instead of fetching full task arrays.**

**Proof of Concept:**
```bash
# Enable query logging in a terminal to see the N+1 problem:
export DEBUG="prisma:*"
npm run dev

# In another terminal, call this endpoint
export TOKEN="<your_token>"
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:3000/api/projects"

# In the first terminal, you'll see:
# - 1 query to fetch user memberships
# - 1 query per membership to fetch all tasks (N+1 problem)
# - 50 memberships = 50+ separate task queries instead of 1 COUNT(*) query

# Example: With 10 projects, you'll see:
# - Query 1: SELECT * FROM memberships WHERE userId = '...'
# - Query 2-11: SELECT * FROM tasks WHERE projectId = '...' (repeated 10 times!)
# Instead of: 1 query with COUNT(*) aggregation
```

---

## 🟡 MEDIUM — System Maintainability & Debugging

### 5. No Error Handling Middleware
**Category:** Architecture | **Severity:** MEDIUM  
**File:** Multiple endpoints (e.g., [src/app/api/projects/route.ts](src/app/api/projects/route.ts), [src/app/api/tasks/[id]/route.ts](src/app/api/tasks/[id]/route.ts#L1-50))

Every route handler duplicates error handling logic inline—validation, auth checks, and response formatting. This creates inconsistent error messages, makes debugging difficult, and increases maintenance burden across 10+ endpoints. **Implement Next.js error middleware or wrapper function to standardize error handling and responses.**

**Proof of Concept — Inconsistent Error Responses:**
```bash
# Error 1: Missing auth header
curl -X GET http://localhost:3000/api/projects
# Returns: {"error":"unauthorized"}

# Error 2: Invalid JSON in POST
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d 'invalid json'
# Returns: 500 with generic error (inconsistent!)

# Error 3: Validation failure
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test","password":"123"}'
# Returns: {"error":"invalid input","details":{...}} (different format!)

# Error 4: Not found
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:3000/api/projects/nonexistent"
# Returns: {"error":"not found"} (another format variant)

# Problem: Clients must handle 4+ different error response shapes
# Solution: Standardize all errors to one format with middleware
```

---

---

## 🔵 Exploratory Findings

### 6. Missing Validation Error Messages on Login/Registration
**Category:** User Experience | **Severity:** MEDIUM

> When a user submits invalid credentials (e.g., invalid email format, weak password, existing email on registration), the app silently fails or shows generic error messages, but it should display specific, actionable validation messages for each field.

**Explanation:**  
The authentication endpoints lack detailed validation feedback. Users cannot understand what went wrong with their input (e.g., "Password must be at least 8 characters" vs. just "Invalid input"). This creates a poor user experience and makes the app appear broken rather than helpful.

**Affected Files:**
- [src/app/api/auth/login/route.ts](src/app/api/auth/login/route.ts)
- [src/app/api/auth/register/route.ts](src/app/api/auth/register/route.ts)
- [src/schemas/auth.ts](src/schemas/auth.ts)

---

### 7. Cached User Data Persists After Sign Out
**Category:** Security/Privacy | **Severity:** MEDIUM

> When a user signs out, the app retains cached user data and project information in memory/local storage, but it should clear all cached data so subsequent login attempts show only the new user's data.

**Explanation:**  
After logout, if a previously logged-in user's session data remains in the cache, a new user logging into the same browser/device could potentially see remnants of the previous user's projects, tasks, or personal information before the cache is fully refreshed. This violates privacy expectations and could expose sensitive information in shared environments.

**Affected Files:**
- [src/components/QueryProvider.tsx](src/components/QueryProvider.tsx)
- [src/app/api/auth/login/route.ts](src/app/api/auth/login/route.ts)
- [src/lib/api-client.ts](src/lib/api-client.ts)

---

### 8. Missing Route Protection with Proper Middleware/Loader
**Category:** Architecture | **Severity:** MEDIUM

> When a user accesses a protected route (e.g., `/dashboard`, `/projects/[id]`) without a valid authentication token, the app redirects to the dashboard first and then redirects to login, but it should implement proper middleware or page loaders that check authentication before rendering and redirect directly to login if no token is found.

**Explanation:**  
Currently, authentication is checked inside page components with manual redirects, causing unnecessary page renders and confusing redirect chains. Proper Next.js middleware or loaders should validate tokens at request-time before any page loads, providing a cleaner user experience and better security by preventing any unauthenticated access to protected pages.

**Affected Files:**
- [src/app/dashboard/page.tsx](src/app/dashboard/page.tsx)
- [src/app/projects/[id]/page.tsx](src/app/projects/[id]/page.tsx)
- [src/app/layout.tsx](src/app/layout.tsx)
- [src/lib/auth.ts](src/lib/auth.ts)

---

## Summary of Priority

| Priority | Issue | Impact | Effort |
|----------|-------|--------|--------|
| 1 | SQL Injection | 🔴 Complete DB compromise | Low |
| 2 | Missing Auth on PATCH | 🔴 Unauthorized data modification | Low |
| 3 | Hard Deletes | 🟠 Permanent data loss | High |
| 4 | N+1 Queries | 🟠 Severe performance degradation | Medium |
| 5 | Error Middleware | 🟡 Maintainability debt | Medium |
| 6 | Missing Validation Messages | 🔵 Poor UX | Low |
| 7 | Cached Data After Logout | 🔵 Privacy/Security concern | Medium |
| 8 | Missing Auth Middleware | 🔵 Architecture issue | Medium |

