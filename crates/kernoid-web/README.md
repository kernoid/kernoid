# kernoid-web

kernoid's login UI and web app (the `web/` directory of [kernoid](https://github.com/kernoid/kernoid)), built, as
tables of files: `kernoid_web::LOGIN_UI` and `kernoid_web::WEB_APP`. kernoid-server serves them at `/login` and `/app`.

In the repository, the build script takes the builds from `web/login/dist` and `web/app/dist` (`pnpm build` in
`web/`); without them the tables are empty. The package on crates.io carries a copy of both in `dist/`, made when
kernoid is released (`scripts/web-crate.sh`), without source maps. The sources are in the repository.

AGPL-3.0-or-later.
