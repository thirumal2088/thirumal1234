Rainbow Sports Attendance — source backup

Live admin:
https://rainbow-sports-attendance-demo.thirumal2088.chatgpt.site/admin
Staff attendance:
https://rainbow-sports-attendance-demo.thirumal2088.chatgpt.site/

This ZIP contains the published source and its database schema migrations.
Staff records, photos, advances, and voice notes are stored in the live
database and are not included in this source backup.

worker/index.js: application source
drizzle/: database schema migrations
dist/: built worker and deployment manifest

The application requires a server-side Worker, a D1 database bound as DB,
and the Sites sign-in integration for administrator identity. GitHub can
store the source; GitHub Pages alone cannot run the app. The manifest
identifies the existing Sites project.
