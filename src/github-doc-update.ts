// src/github-doc-update.ts

export interface UpdateDocParams {
	action: "create" | "update";
	file_path: string;
	content: string;
	commit_message: string;
	pr_title?: string;
	pr_description?: string;
	branch_name?: string;
	base_branch?: string;
}

export interface UpdateResult {
	success: boolean;
	branch: string;
	file_path: string;
	action: string;
	commit_sha?: string;
	pr_url?: string;
	pr_number?: number;
	error?: string;
}

export interface PRDetails {
	title: string;
	body: string;
	head: string;
	base: string;
}

/**
 * Service for updating GitHub documentation files
 */
export class GitHubDocService {
	private githubToken: string;
	private owner: string;
	private repo: string;
	private apiBase: string;

	constructor(
		githubToken: string,
		owner: string,
		repo: string,
		apiBase = "https://api.github.com",
	) {
		this.githubToken = githubToken;
		this.owner = owner;
		this.repo = repo;
		this.apiBase = apiBase.replace(/\/$/, ""); // Remove trailing slash
	}

	/**
	 * Main method to update documentation
	 */
	async updateDocument(params: UpdateDocParams): Promise<UpdateResult> {
		try {
			const baseBranch = params.base_branch || "main";
			const branch = params.branch_name || `docs-update-${Date.now()}`;

			// Get the base branch SHA
			const baseSha = await this.getBranchSHA(baseBranch);

			// Create the new branch
			await this.createBranch(branch, baseSha);

			// Create or update the file
			const commitResult = await this.createOrUpdateFile(
				branch,
				params.file_path,
				params.content,
				params.commit_message,
			);

			const result: UpdateResult = {
				success: true,
				branch,
				file_path: params.file_path,
				action: params.action,
				commit_sha: commitResult.sha,
			};

			// Create PR if requested
			if (params.pr_title) {
				const prResult = await this.createPR({
					title: params.pr_title,
					body: params.pr_description || `Updates ${params.file_path}`,
					head: branch,
					base: baseBranch,
				});
				result.pr_url = prResult.html_url;
				result.pr_number = prResult.number;
			}

			return result;
		} catch (error) {
			return {
				success: false,
				branch: params.branch_name || "unknown",
				file_path: params.file_path,
				action: params.action,
				error:
					error instanceof Error
						? error.message
						: "Unknown error occurred",
			};
		}
	}

	/**
	 * Get the SHA of a branch
	 */
	private async getBranchSHA(branch: string): Promise<string> {
		const url = `${this.apiBase}/repos/${this.owner}/${this.repo}/git/ref/heads/${branch}`;
		const response = await fetch(url, {
			headers: this.getHeaders(),
		});

		if (!response.ok) {
			throw new Error(`Failed to get branch ${branch}: ${response.status}`);
		}

		const data = (await response.json()) as {
			object: { sha: string };
		};
		return data.object.sha;
	}

	/**
	 * Create a new branch
	 */
	private async createBranch(branchName: string, sha: string): Promise<void> {
		const url = `${this.apiBase}/repos/${this.owner}/${this.repo}/git/refs`;
		const response = await fetch(url, {
			method: "POST",
			headers: this.getHeaders(),
			body: JSON.stringify({
				ref: `refs/heads/${branchName}`,
				sha,
			}),
		});

		if (!response.ok) {
			const error = await response.text();
			throw new Error(
				`Failed to create branch ${branchName}: ${response.status} - ${error}`,
			);
		}
	}

	/**
	 * Create or update a file in the repository
	 */
	private async createOrUpdateFile(
		branch: string,
		filePath: string,
		content: string,
		message: string,
	): Promise<{ sha: string }> {
		// First, try to get the current file to see if it exists
		let currentSha: string | undefined;
		try {
			const existingFile = await this.getFileContent(filePath, branch);
			currentSha = existingFile.sha;
		} catch {
			// File doesn't exist, which is fine for creation
		}

		const url = `${this.apiBase}/repos/${this.owner}/${this.repo}/contents/${filePath}`;
		const body: {
			message: string;
			content: string;
			branch: string;
			sha?: string;
		} = {
			message,
			content: Buffer.from(content, "utf-8").toString("base64"),
			branch,
		};

		// Include SHA if file exists (for updates)
		if (currentSha) {
			body.sha = currentSha;
		}

		const response = await fetch(url, {
			method: "PUT",
			headers: this.getHeaders(),
			body: JSON.stringify(body),
		});

		if (!response.ok) {
			const error = await response.text();
			throw new Error(
				`Failed to ${currentSha ? "update" : "create"} file ${filePath}: ${response.status} - ${error}`,
			);
		}

		const data = (await response.json()) as {
			commit: { sha: string };
		};
		return { sha: data.commit.sha };
	}

	/**
	 * Get file content from repository
	 */
	private async getFileContent(
		filePath: string,
		branch?: string,
	): Promise<{ content: string; sha: string }> {
		let url = `${this.apiBase}/repos/${this.owner}/${this.repo}/contents/${filePath}`;
		if (branch) {
			url += `?ref=${branch}`;
		}

		const response = await fetch(url, {
			headers: this.getHeaders(),
		});

		if (!response.ok) {
			throw new Error(`File not found: ${filePath}`);
		}

		const data = (await response.json()) as {
			content: string;
			sha: string;
			encoding: string;
		};

		return {
			content: Buffer.from(data.content, "base64").toString("utf-8"),
			sha: data.sha,
		};
	}

	/**
	 * Create a pull request
	 */
	private async createPR(details: PRDetails): Promise<{
		html_url: string;
		number: number;
	}> {
		const url = `${this.apiBase}/repos/${this.owner}/${this.repo}/pulls`;
		const response = await fetch(url, {
			method: "POST",
			headers: this.getHeaders(),
			body: JSON.stringify({
				title: details.title,
				body: details.body,
				head: details.head,
				base: details.base,
			}),
		});

		if (!response.ok) {
			const error = await response.text();
			throw new Error(
				`Failed to create pull request: ${response.status} - ${error}`,
			);
		}

		const data = (await response.json()) as {
			html_url: string;
			number: number;
		};
		return {
			html_url: data.html_url,
			number: data.number,
		};
	}

	/**
	 * Get standard headers for GitHub API requests
	 */
	private getHeaders(): Record<string, string> {
		return {
			Authorization: `Bearer ${this.githubToken}`,
			Accept: "application/vnd.github+json",
			"Content-Type": "application/json",
			"X-GitHub-Api-Version": "2022-11-28",
			"User-Agent": "asi-mcp-worker/1.0",
		};
	}
}