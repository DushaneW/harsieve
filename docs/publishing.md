# Publish to GitHub

No repository was created, no release published and no messages posted.

Create an empty repository named harsieve under DushaneW, with your chosen
visibility. Do not initialize a second README or license. In the extracted
harsieve directory:

~~~sh
git init -b main
git add .
git diff --cached --stat
git commit -m "feat: add offline HAR privacy projection and waterfall reports"
git remote add origin https://github.com/DushaneW/harsieve.git
git push -u origin main
~~~

Use your own local Git identity and authentication. If a repository already
exists, clone it and review an import instead of force-pushing. Include the
.github directory; uploading only visible files misses CI and review templates.

After the first push, inspect Actions, enable private vulnerability reporting,
and configure branch protection if desired. CODEOWNERS does not enforce reviews
by itself. See research-and-launch.md for suggested metadata and launch steps.

The source tree does not include real HAR captures. Compiled distributions in
the supplied delivery folder are release artifacts, not files to commit to main.
