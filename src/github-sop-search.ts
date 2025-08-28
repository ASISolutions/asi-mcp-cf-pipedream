// src/github-sop-search.ts
import { parse as yamlParse } from 'yaml';

// ---- Types ----
export interface SOPSearchResult {
	path: string;
	metadata: SOPMetadata;
	content: string;
	raw: string;
}

export interface SOPMetadata {
	process_code?: string;
	title?: string;
	category?: string;
	type?: string;
	search_terms?: string[];
	description?: string;
	systems?: Record<string, {
		operations?: string[];
		required?: boolean;
		pipedream_app?: string;
		display_name?: string;
		api_version?: string;
		base_url?: string;
		auth?: {
			type: string;
			scopes?: string[];
			environment?: string;
		};
		defaults?: Record<string, string>;
		[key: string]: any;
	}>;
	estimated_time?: string;
	requires_approval?: boolean;
	compliance?: string[];
	prerequisites?: string[];
	related_processes?: Record<string, string>;
	last_modified?: string;
	owner?: string;
	version?: string;
	[key: string]: any;
}

export interface SearchOptions {
	searchType?: 'process' | 'quick' | 'system' | 'sales' | 'finance' | 'operations' | 'support';
	system?: string;
	limit?: number;
	includeContent?: boolean;
}

export interface SystemConfig {
	pipedream_app: string;
	display_name: string;
	api_version?: string;
	base_url?: string;
	auth?: {
		type: string;
		scopes?: string[];
		environment?: string;
	};
	defaults?: Record<string, string>;
	test_endpoint?: {
		method: string;
		url: string;
		expected_status: number;
	};
	[key: string]: any;
}

// ---- GitHub SOP Search Service ----
export class SOPSearchService {
	private owner: string;
	private repo: string;
	private branch: string;
	private githubToken: string;

	constructor(githubToken: string, owner = 'asi-solutions', repo = 'sop-docs', branch = 'main') {
		this.githubToken = githubToken;
		this.owner = owner;
		this.repo = repo;
		this.branch = branch;
	}

	/**
	 * Main search method - interprets user intent and searches appropriately
	 */
	async search(userQuery: string, options: SearchOptions = {}): Promise<SOPSearchResult[]> {
		// Check for direct process code
		const processCode = this.extractProcessCode(userQuery);
		if (processCode) {
			const result = await this.getByProcessCode(processCode);
			return result ? [result] : [];
		}

		// Build and execute search
		const searchQuery = this.buildSearchQuery(userQuery, options);
		
		try {
			const response = await fetch(`https://api.github.com/search/code?q=${encodeURIComponent(searchQuery)}&sort=indexed&per_page=${options.limit || 5}`, {
				headers: {
					'Authorization': `Bearer ${this.githubToken}`,
					'Accept': 'application/vnd.github+json',
					'X-GitHub-Api-Version': '2022-11-28',
					'User-Agent': 'asi-mcp-worker/1.0'
				}
			});

			if (!response.ok) {
				throw new Error(`GitHub search failed: ${response.status}`);
			}

			const data = await response.json() as { items: Array<{ path: string }> };
			
			// Fetch full content for each result
			const results = await Promise.allSettled(
				data.items.map(item => this.fetchDocument(item.path, options.includeContent))
			);

			return results
				.filter((result): result is PromiseFulfilledResult<SOPSearchResult> => 
					result.status === 'fulfilled' && result.value !== null
				)
				.map(result => result.value);
		} catch (error) {
			console.error('GitHub search error:', error);
			throw new Error(`Search failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
		}
	}

	/**
	 * Build GitHub search query from user input
	 */
	buildSearchQuery(userQuery: string, options: SearchOptions): string {
		let query = `repo:${this.owner}/${this.repo} `;

		// Add path filters based on search type
		if (options.searchType) {
			const pathMap: Record<string, string> = {
				'process': 'path:docs/processes',
				'quick': 'path:docs/quick-actions',
				'system': 'path:docs/systems',
				'sales': 'path:docs/processes/sales',
				'finance': 'path:docs/processes/finance',
				'operations': 'path:docs/processes/operations',
				'support': 'path:docs/processes/support'
			};
			
			if (pathMap[options.searchType]) {
				query += `${pathMap[options.searchType]} `;
			}
		}

		// Add system filter if specified
		if (options.system) {
			query += `systems:${options.system} `;
		}

		// Add the search terms - handle quoted phrases
		const cleanedQuery = userQuery.trim();
		if (cleanedQuery.includes('"')) {
			// Pass through quoted phrases as-is
			query += `${cleanedQuery} `;
		} else {
			// For unquoted terms, let GitHub handle the tokenization
			query += `${cleanedQuery} `;
		}

		// Always filter to markdown files
		query += 'extension:md';

		return query.trim();
	}

	/**
	 * Extract process code from user query (e.g., SALES-001, FINANCE-002)
	 */
	extractProcessCode(query: string): string | null {
		const match = query.match(/\b([A-Z]+)-(\d{3})\b/);
		return match ? match[0] : null;
	}

	/**
	 * Get document by process code
	 */
	async getByProcessCode(processCode: string): Promise<SOPSearchResult | null> {
		const searchQuery = `repo:${this.owner}/${this.repo} process_code:${processCode} extension:md`;
		
		try {
			const response = await fetch(`https://api.github.com/search/code?q=${encodeURIComponent(searchQuery)}&per_page=1`, {
				headers: {
					'Authorization': `Bearer ${this.githubToken}`,
					'Accept': 'application/vnd.github+json',
					'X-GitHub-Api-Version': '2022-11-28',
					'User-Agent': 'asi-mcp-worker/1.0'
				}
			});

			if (!response.ok) {
				throw new Error(`GitHub search failed: ${response.status}`);
			}

			const data = await response.json() as { items: Array<{ path: string }> };
			
			if (data.items.length > 0) {
				return await this.fetchDocument(data.items[0].path, true);
			}
			return null;
		} catch (error) {
			console.error('Process code search error:', error);
			return null;
		}
	}

	/**
	 * Fetch full document content with metadata
	 */
	async fetchDocument(path: string, includeContent = true): Promise<SOPSearchResult | null> {
		try {
			const response = await fetch(`https://api.github.com/repos/${this.owner}/${this.repo}/contents/${path}`, {
				headers: {
					'Authorization': `Bearer ${this.githubToken}`,
					'Accept': 'application/vnd.github+json',
					'X-GitHub-Api-Version': '2022-11-28',
					'User-Agent': 'asi-mcp-worker/1.0'
				}
			});

			if (!response.ok) {
				throw new Error(`Failed to fetch document: ${response.status}`);
			}

			const data = await response.json() as { content: string; encoding: string };
			const content = Buffer.from(data.content, 'base64').toString('utf-8');
			const { metadata, body } = this.parseDocument(content);

			// Enrich systems data with configuration
			if (metadata.systems) {
				const enrichedSystems: typeof metadata.systems = {};
				for (const [systemSlug, systemData] of Object.entries(metadata.systems)) {
					const config = await this.getSystemConfig(systemSlug);
					enrichedSystems[systemSlug] = {
						...config,
						...systemData
					};
				}
				metadata.systems = enrichedSystems;
			}

			return {
				path,
				metadata,
				content: includeContent ? body : '',
				raw: content
			};
		} catch (error) {
			console.error(`Error fetching document ${path}:`, error);
			return null;
		}
	}

	/**
	 * Parse document frontmatter and content
	 */
	parseDocument(content: string): { metadata: SOPMetadata; body: string } {
		const frontmatterRegex = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/;
		const match = content.match(frontmatterRegex);

		if (match) {
			try {
				const metadata = yamlParse(match[1]) as SOPMetadata;
				const body = match[2];
				return { metadata, body };
			} catch (error) {
				console.warn('Failed to parse YAML frontmatter:', error);
				return { metadata: {}, body: content };
			}
		}

		return { metadata: {}, body: content };
	}

	/**
	 * Get system configuration by Pipedream app slug
	 */
	async getSystemConfig(systemSlug: string): Promise<SystemConfig> {
		const configPath = `docs/systems/${systemSlug}/_config.yml`;
		
		try {
			const response = await fetch(`https://api.github.com/repos/${this.owner}/${this.repo}/contents/${configPath}`, {
				headers: {
					'Authorization': `Bearer ${this.githubToken}`,
					'Accept': 'application/vnd.github+json',
					'X-GitHub-Api-Version': '2022-11-28',
					'User-Agent': 'asi-mcp-worker/1.0'
				}
			});

			if (!response.ok) {
				// Return minimal config if not found
				return { 
					pipedream_app: systemSlug,
					display_name: systemSlug.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
				};
			}

			const data = await response.json() as { content: string };
			const content = Buffer.from(data.content, 'base64').toString('utf-8');
			return yamlParse(content) as SystemConfig;
		} catch (error) {
			console.warn(`Failed to fetch system config for ${systemSlug}:`, error);
			// Return minimal config if failed
			return { 
				pipedream_app: systemSlug,
				display_name: systemSlug.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
			};
		}
	}

	/**
	 * Search by multiple criteria - helper methods for advanced searches
	 */
	async searchByOwner(email: string): Promise<SOPSearchResult[]> {
		return this.search(`owner:${email}`, { limit: 10 });
	}

	async searchByCompliance(standard: string): Promise<SOPSearchResult[]> {
		return this.search(`compliance:${standard}`, { limit: 10 });
	}

	async searchBySystem(pipedreamSlug: string): Promise<SOPSearchResult[]> {
		return this.search('', { system: pipedreamSlug, limit: 10 });
	}

	async searchRequiringApproval(): Promise<SOPSearchResult[]> {
		return this.search('requires_approval:true', { limit: 10 });
	}

	/**
	 * Get recent updates
	 */
	async getRecentlyModified(limit = 5): Promise<SOPSearchResult[]> {
		const query = `repo:${this.owner}/${this.repo} path:docs/processes extension:md`;
		
		try {
			const response = await fetch(`https://api.github.com/search/code?q=${encodeURIComponent(query)}&sort=indexed&per_page=${limit}`, {
				headers: {
					'Authorization': `Bearer ${this.githubToken}`,
					'Accept': 'application/vnd.github+json',
					'X-GitHub-Api-Version': '2022-11-28',
					'User-Agent': 'asi-mcp-worker/1.0'
				}
			});

			if (!response.ok) {
				throw new Error(`GitHub search failed: ${response.status}`);
			}

			const data = await response.json() as { items: Array<{ path: string }> };
			
			const results = await Promise.allSettled(
				data.items.map(item => this.fetchDocument(item.path, false))
			);

			return results
				.filter((result): result is PromiseFulfilledResult<SOPSearchResult> => 
					result.status === 'fulfilled' && result.value !== null
				)
				.map(result => result.value);
		} catch (error) {
			console.error('Recent search error:', error);
			return [];
		}
	}
}