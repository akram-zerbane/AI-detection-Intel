import gitlab
from typing import Optional

class GitLabService:
    def __init__(self, url: str, private_token: str, project_id: int):
        self.url = url.rstrip('/') if url else ""
        self.private_token = private_token
        self.project_id = project_id
        self.gl: Optional[gitlab.Gitlab] = None
        self.project = None

        if self.url and "<gitlab_ip>" not in self.url and self.private_token and not self.private_token.startswith("glpat-..."):
            try:
                self.gl = gitlab.Gitlab(
                    url=self.url,
                    private_token=self.private_token,
                    user_agent="DetectionAsCode-Agent/1.0",
                    timeout=10
                )
                self.gl.auth()
                self.project = self.gl.projects.get(self.project_id)
                print(f"[+] Connected to GitLab project: {self.project.name} (ID: {self.project_id})")
            except Exception as e:
                print(f"[!] Warning: GitLab connection skipped or failed: {e}")
                self.gl = None
                self.project = None

    def commit_detection_rule(self, rule_yaml: str, rule_name: str, branch_prefix: str = "detection") -> Optional[str]:
        if not self.project:
            print("[!] GitLab integration not configured or project unreachable. Skipping MR creation.")
            return None

        clean_name = rule_name.lower().replace(" ", "_").replace("/", "_")
        branch_name = f"{branch_prefix}/{clean_name}"
        file_path = f"rules/windows/{clean_name}.yml"

        try:
            self.project.branches.create({'branch': branch_name, 'ref': 'main'})
            
            self.project.commits.create({
                'branch': branch_name,
                'commit_message': f"feat(detection): auto-generated rule for {rule_name}",
                'actions': [{'action': 'create', 'file_path': file_path, 'content': rule_yaml}]
            })

            mr = self.project.mergerequests.create({
                'source_branch': branch_name,
                'target_branch': 'main',
                'title': f"Draft: Autonomous Sigma Rule - {rule_name}",
                'description': f"Automated detection rule synthesized by AI Agent for `{rule_name}`."
            })
            return mr.web_url
        except Exception as e:
            print(f"[!] Error committing to GitLab: {e}")
            return None

    def update_file_commit(self, file_path: str, branch: str, content: str, commit_message: str) -> bool:
        if not self.project:
            print("[!] GitLab integration not configured or project unreachable.")
            return False

        try:
            action = 'update'
            try:
                self.project.files.get(file_path=file_path, ref=branch)
            except gitlab.exceptions.GitlabGetError:
                action = 'create'

            self.project.commits.create({
                'branch': branch,
                'commit_message': commit_message,
                'actions': [{
                    'action': action,
                    'file_path': file_path,
                    'content': content
                }]
            })
            print(f"[+] Successfully committed {action} for {file_path} on branch {branch}")
            return True
        except Exception as e:
            print(f"[!] Error pushing commit to GitLab: {e}")
            return False

    def commit_staging_rule_with_fixture(
        self,
        technique_id: str,
        rule_yaml: str,
        raw_telemetry_json: str,
        branch: str = "main"
    ) -> bool:
        """
        Atomically commits the technique test fixture and the staging Sigma rule
        with sanitized, unique file names based on the technique ID.
        """
        if not self.project:
            print("[!] GitLab integration not configured or project unreachable.")
            return False

        tech_upper = (
            technique_id.strip()
            .upper()
            .replace(".", "_")
            .replace("/", "_")
            .replace(" ", "_")
        )
        clean_name = f"caldera_{tech_upper.lower()}"
        
        fixture_path = f"data/techniques/{tech_upper}.json"
        rule_path = f"rules/rules_staging/{clean_name}.yml"

        actions = []
        for path, data in [(fixture_path, raw_telemetry_json), (rule_path, rule_yaml)]:
            action = "update"
            try:
                self.project.files.get(file_path=path, ref=branch)
            except gitlab.exceptions.GitlabGetError:
                action = "create"
            actions.append({
                "action": action,
                "file_path": path,
                "content": data
            })

        try:
            self.project.commits.create({
                "branch": branch,
                "commit_message": f"feat(dac): synthesize rule and telemetry fixture for {tech_upper} [skip-ai]",
                "actions": actions
            })
            print(f"[+] Atomically committed {fixture_path} and {rule_path} to {branch}")
            return True
        except Exception as e:
            print(f"[!] Error committing staging files: {e}")
            return False
