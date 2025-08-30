// src/user-provisioning.ts
import type { Env } from "./index";
import type { Props } from "./workers-oauth-utils";

export interface ProvisioningResult {
	success: boolean;
	error?: string;
	gitbookSpaceUrl?: string;
}

export interface UserSignupData {
	tenant: string;
	sub: string;
	email: string;
	name?: string;
	domain: string;
}

export class UserProvisioningService {
	constructor(private env: Env) {}

	/**
	 * Check if a domain already has users signed up (domain blocking logic)
	 */
	async isDomainBlocked(domain: string): Promise<{ blocked: boolean; reason?: string }> {
		// Check if any tenant already exists for this domain
		const domainKey = `domain:${domain}:tenant`;
		const existingTenant = await this.env.USER_LINKS.get(domainKey);
		
		if (existingTenant) {
			return {
				blocked: true,
				reason: `Domain ${domain} is already registered. Please contact your organization administrator or use a different email domain.`
			};
		}

		return { blocked: false };
	}

	/**
	 * Register a domain to a tenant (first user from domain claims it)
	 */
	async registerDomainToTenant(domain: string, tenant: string): Promise<void> {
		const domainKey = `domain:${domain}:tenant`;
		await this.env.USER_LINKS.put(domainKey, tenant);
	}

	/**
	 * Create initial user record and start provisioning
	 */
	async createUser(signupData: UserSignupData): Promise<void> {
		const { tenant, sub, email, name, domain } = signupData;
		
		// Register domain to this tenant (if not already registered)
		await this.registerDomainToTenant(domain, tenant);

		// Create user profile
		const userProfileKey = `tenant:${tenant}:user:${sub}:profile`;
		await this.env.USER_LINKS.put(userProfileKey, JSON.stringify({
			email,
			name,
			domain,
			createdAt: new Date().toISOString()
		}));

		// Set trial period (30 days from now)
		const trialStarted = new Date();
		const trialExpires = new Date(trialStarted.getTime() + (30 * 24 * 60 * 60 * 1000));

		const trialStartedKey = `tenant:${tenant}:trial:started`;
		const trialExpiresKey = `tenant:${tenant}:trial:expires`;
		
		await this.env.USER_LINKS.put(trialStartedKey, trialStarted.toISOString());
		await this.env.USER_LINKS.put(trialExpiresKey, trialExpires.toISOString());

		// Set initial provisioning status
		const statusKey = `tenant:${tenant}:user:${sub}:status`;
		await this.env.USER_LINKS.put(statusKey, "provisioning");

		// Store tenant metadata
		const tenantSettingsKey = `tenant:${tenant}:settings`;
		await this.env.USER_LINKS.put(tenantSettingsKey, JSON.stringify({
			domain,
			primaryUser: sub,
			createdAt: trialStarted.toISOString(),
			status: "active"
		}));
	}

	/**
	 * Check if user already exists
	 */
	async userExists(tenant: string, sub: string): Promise<boolean> {
		const userProfileKey = `tenant:${tenant}:user:${sub}:profile`;
		const profile = await this.env.USER_LINKS.get(userProfileKey);
		return profile !== null;
	}

	/**
	 * Get user provisioning status
	 */
	async getUserStatus(tenant: string, sub: string): Promise<"provisioning" | "complete" | "error" | null> {
		const statusKey = `tenant:${tenant}:user:${sub}:status`;
		const status = await this.env.USER_LINKS.get(statusKey);
		return status as "provisioning" | "complete" | "error" | null;
	}

	/**
	 * Provision GitBook space for the tenant
	 */
	async provisionGitBookSpace(tenant: string, userEmail: string): Promise<ProvisioningResult> {
		try {
			// Extract domain from tenant for space naming
			const spaceName = `ASI Connect - ${tenant}`;
			const spaceDescription = `Getting started documentation and guides for ${tenant}`;

			// Create GitBook space via API
			const createSpaceResponse = await fetch("https://api.gitbook.com/v1/spaces", {
				method: "POST",
				headers: {
					"Authorization": `Bearer ${this.env.GITBOOK_API_TOKEN}`,
					"Content-Type": "application/json"
				},
				body: JSON.stringify({
					title: spaceName,
					description: spaceDescription,
					visibility: "private",
					organization: this.env.GITBOOK_ORGANIZATION_ID
				})
			});

			if (!createSpaceResponse.ok) {
				const errorText = await createSpaceResponse.text();
				console.error("GitBook space creation failed:", errorText);
				return {
					success: false,
					error: `Failed to create GitBook space: ${createSpaceResponse.status} ${errorText}`
				};
			}

			const spaceData = await createSpaceResponse.json() as any;
			const spaceId = spaceData.id;
			const spaceUrl = spaceData.urls?.app || `https://app.gitbook.com/spaces/${spaceId}`;

			// Store GitBook space information
			const gitbookSpaceIdKey = `tenant:${tenant}:gitbook:space_id`;
			const gitbookSpaceUrlKey = `tenant:${tenant}:gitbook:space_url`;
			const gitbookGettingStartedKey = `tenant:${tenant}:gitbook:getting_started_url`;

			await this.env.USER_LINKS.put(gitbookSpaceIdKey, spaceId);
			await this.env.USER_LINKS.put(gitbookSpaceUrlKey, spaceUrl);
			await this.env.USER_LINKS.put(gitbookGettingStartedKey, `${spaceUrl}/getting-started`);

			return {
				success: true,
				gitbookSpaceUrl: spaceUrl
			};

		} catch (error) {
			console.error("GitBook provisioning error:", error);
			return {
				success: false,
				error: `GitBook provisioning failed: ${error instanceof Error ? error.message : 'Unknown error'}`
			};
		}
	}

	/**
	 * Complete user provisioning process
	 */
	async completeProvisioning(tenant: string, sub: string): Promise<ProvisioningResult> {
		try {
			// Get user profile to extract email
			const userProfileKey = `tenant:${tenant}:user:${sub}:profile`;
			const profileData = await this.env.USER_LINKS.get(userProfileKey);
			
			if (!profileData) {
				return {
					success: false,
					error: "User profile not found"
				};
			}

			const profile = JSON.parse(profileData);
			
			// Provision GitBook space
			const gitbookResult = await this.provisionGitBookSpace(tenant, profile.email);
			
			if (!gitbookResult.success) {
				// Mark as error
				const statusKey = `tenant:${tenant}:user:${sub}:status`;
				await this.env.USER_LINKS.put(statusKey, "error");
				
				return gitbookResult;
			}

			// Mark provisioning as complete
			const statusKey = `tenant:${tenant}:user:${sub}:status`;
			await this.env.USER_LINKS.put(statusKey, "complete");

			// Store completion timestamp
			const completedKey = `tenant:${tenant}:user:${sub}:provisioned_at`;
			await this.env.USER_LINKS.put(completedKey, new Date().toISOString());

			return {
				success: true,
				gitbookSpaceUrl: gitbookResult.gitbookSpaceUrl
			};

		} catch (error) {
			console.error("Provisioning completion error:", error);
			
			// Mark as error
			const statusKey = `tenant:${tenant}:user:${sub}:status`;
			await this.env.USER_LINKS.put(statusKey, "error");

			return {
				success: false,
				error: `Provisioning failed: ${error instanceof Error ? error.message : 'Unknown error'}`
			};
		}
	}

	/**
	 * Get user's GitBook space URL if provisioned
	 */
	async getGitBookSpaceUrl(tenant: string): Promise<string | null> {
		const gitbookSpaceUrlKey = `tenant:${tenant}:gitbook:space_url`;
		return await this.env.USER_LINKS.get(gitbookSpaceUrlKey);
	}

	/**
	 * Get user's trial information
	 */
	async getTrialInfo(tenant: string): Promise<{
		started: string | null;
		expires: string | null;
		daysRemaining: number | null;
		isExpired: boolean;
	}> {
		const trialStartedKey = `tenant:${tenant}:trial:started`;
		const trialExpiresKey = `tenant:${tenant}:trial:expires`;

		const [started, expires] = await Promise.all([
			this.env.USER_LINKS.get(trialStartedKey),
			this.env.USER_LINKS.get(trialExpiresKey)
		]);

		if (!expires) {
			return { started, expires, daysRemaining: null, isExpired: false };
		}

		const expiresDate = new Date(expires);
		const now = new Date();
		const msRemaining = expiresDate.getTime() - now.getTime();
		const daysRemaining = Math.max(0, Math.ceil(msRemaining / (24 * 60 * 60 * 1000)));

		return {
			started,
			expires,
			daysRemaining,
			isExpired: msRemaining <= 0
		};
	}
}