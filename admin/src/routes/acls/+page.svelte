<script lang="ts">
import { onMount } from 'svelte';

// Data state
let users: string[] = [];
let selectedUser: string | null = null;
let userAcls: any[] = [];
let dashboardError = '';
let dashboardLoading = false;

// Form state
let newPermission = {
	callLetters: '',
	frequency: 'FM',
	canReceive: false,
	canSend: false
};

// Save progress state
let saveProgress = {
	active: false,
	message: '',
	retryCount: 0,
	maxRetries: 5
};

function getToken() {
	return localStorage.getItem('admin_token');
}

onMount(() => {
	loadUsers();
});

async function loadUsers() {
	dashboardLoading = true;
	dashboardError = '';
	try {
		const token = getToken();
		if (!token) {
			throw new Error('No authentication token found');
		}
		
		// Reset session timeout for API activity
		if (typeof window !== 'undefined' && (window as any).resetSessionTimeout) {
			(window as any).resetSessionTimeout();
		}
		
		const res = await fetch(`/admin/api/users?t=${Date.now()}`, {
			headers: { Authorization: `Bearer ${token}` }
		});
		
		if (!res.ok) {
			const errorText = await res.text();
			throw new Error(`Failed to load users: ${res.status} ${errorText}`);
		}
		
		const data = await res.json();
		console.log('Loaded users:', data.users);
		users = data.users || [];
	} catch (e: any) {
		console.error('Load users error:', e);
		dashboardError = e.message || 'Failed to load users';
	} finally {
		dashboardLoading = false;
	}
}

async function selectUser(user: string) {
	selectedUser = user;
	userAcls = [];
	dashboardError = '';
	clearNewPermission();
	
	try {
		const token = getToken();
		if (!token) {
			throw new Error('No authentication token found');
		}
		
		// Reset session timeout for API activity
		if (typeof window !== 'undefined' && (window as any).resetSessionTimeout) {
			(window as any).resetSessionTimeout();
		}
		
		const res = await fetch(`/admin/api/user-details?username=${encodeURIComponent(user)}`, {
			headers: { Authorization: `Bearer ${token}` }
		});
		if (!res.ok) throw new Error('Failed to load user details');
		const data = await res.json();
		userAcls = data.acls || [];
	} catch (e: any) {
		dashboardError = e.message || 'Failed to load user details';
	}
}

function clearNewPermission() {
	newPermission = {
		callLetters: '',
		frequency: 'FM',
		canReceive: false,
		canSend: false
	};
}

function addPermission() {
	const callLetters = newPermission.callLetters.trim().toUpperCase();
	
	if (!callLetters) {
		dashboardError = 'Call Letters are required';
		return;
	}
	
	if (callLetters.length < 3) {
		dashboardError = 'Call Letters must be at least 3 characters';
		return;
	}
	
	if (!newPermission.canReceive && !newPermission.canSend) {
		dashboardError = 'At least one permission (Receive or Send) must be selected';
		return;
	}
	
	// Create the topic name in lowercase for storage
	const topicName = `${callLetters.toLowerCase()}_${newPermission.frequency.toLowerCase()}`;
	
	// Check if permission already exists for this call letters
	const existingIndex = userAcls.findIndex(acl => acl.topic === `carrelink/${topicName}/relays`);
	if (existingIndex !== -1) {
		dashboardError = `Permission for Call Letters "${callLetters} ${newPermission.frequency}" already exists`;
		return;
	}
	
	// Create the ACL object with the new format
	const acl = {
		topic: `carrelink/${topicName}/relays`,
		permission: 'allow',
		action: newPermission.canReceive && newPermission.canSend ? 'all' : 
			   newPermission.canReceive ? 'subscribe' : 'publish'
	};
	
	userAcls = [...userAcls, acl];
	clearNewPermission();
	dashboardError = '';
}

function removePermission(index: number) {
	userAcls = userAcls.filter((_, i) => i !== index);
}

async function saveAcls() {
	if (!selectedUser) return;
	
	// Start save progress
	saveProgress = {
		active: true,
		message: 'Saving permissions... this may take a moment while it propagates to the network...',
		retryCount: 0,
		maxRetries: 5
	};
	dashboardError = '';
	
	// Run the save operation in the background
	setTimeout(async () => {
		try {
			const token = getToken();
			if (!token) {
				throw new Error('No authentication token found');
			}
			
			// Reset session timeout for API activity
			if (typeof window !== 'undefined' && (window as any).resetSessionTimeout) {
				(window as any).resetSessionTimeout();
			}
			
			console.log('Saving ACLs for user:', selectedUser);
			const res = await fetch('/admin/api/user-acls', {
				method: 'PUT',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${token}`
				},
				body: JSON.stringify({
					username: selectedUser,
					acls: userAcls
				})
			});
			
			if (!res.ok) {
				const errorText = await res.text();
				throw new Error(`Failed to save permissions: ${res.status} ${errorText}`);
			}
			
			console.log('ACLs saved successfully');
			
			// Implement retry mechanism to confirm ACLs are saved
			const retryDelay = 5000; // 5 seconds
			
			while (saveProgress.retryCount < saveProgress.maxRetries) {
				saveProgress.retryCount++;
				saveProgress.message = `Saving permissions... this may take a moment while it propagates to the network... (Attempt ${saveProgress.retryCount}/${saveProgress.maxRetries})`;
				
				console.log(`Retry ${saveProgress.retryCount}/${saveProgress.maxRetries} - waiting ${retryDelay}ms...`);
				await new Promise(resolve => setTimeout(resolve, retryDelay));
				
				// Reload user details to confirm ACLs are saved
				try {
					const reloadRes = await fetch(`/admin/api/user-details?username=${encodeURIComponent(selectedUser!)}`, {
						headers: { Authorization: `Bearer ${token}` }
					});
					if (reloadRes.ok) {
						const data = await reloadRes.json();
						const reloadedAcls = data.acls || [];
						
						// Check if ACLs match (simple length check for now)
						if (reloadedAcls.length === userAcls.length) {
							console.log('ACLs confirmed saved after retry');
							break;
						}
					}
				} catch (e) {
					console.warn('Failed to reload user details during retry:', e);
				}
			}
			
		} catch (e: any) {
			console.error('Save ACLs error:', e);
			dashboardError = e.message || 'Failed to save permissions';
		} finally {
			saveProgress.active = false;
		}
	}, 0);
}

function formatPermission(action: string): string {
	switch (action) {
		case 'all': return 'Receive & Send';
		case 'subscribe': return 'Receive Only';
		case 'publish': return 'Send Only';
		default: return action;
	}
}

function getCallLettersFromTopic(topic: string): { callLetters: string; frequency: string } {
	// Extract call letters and frequency from "carrelink/callsign_frequency/relays" format
	const match = topic.match(/^carrelink\/(.+)_(.+)\/relays$/);
	if (match) {
		return {
			callLetters: match[1].toUpperCase(),
			frequency: match[2].toUpperCase()
		};
	}
	// Fallback for unexpected format
	return {
		callLetters: topic,
		frequency: 'FM'
	};
}
</script>

<div class="dashboard-title">Permission Management</div>

{#if dashboardError}
	<div class="dashboard-error">{dashboardError}</div>
{/if}

<div class="acl-management-container">
	<!-- Left side: User list -->
	<div class="user-list-section">
		<div class="list-box">
			<div class="list-header">Users</div>
			<div class="list-content">
				{#if dashboardLoading && users.length === 0}
					<div class="loading-item">Loading users...</div>
				{:else if users.length === 0}
					<div class="empty-item">No users found</div>
				{:else}
					{#each users as user}
						<div 
							class="list-item {selectedUser === user ? 'selected' : ''}" 
							on:click={() => selectUser(user)}
							on:keydown={(e) => e.key === 'Enter' && selectUser(user)}
							role="button"
							tabindex="0"
						>
							{user}
						</div>
					{/each}
				{/if}
			</div>
		</div>
	</div>

	<!-- Right side: ACL form -->
	<div class="acl-section">
		<div class="form-group-box">
			<div class="form-header">
				{#if selectedUser}
					Permissions for {selectedUser}
				{:else}
					User Permissions
				{/if}
			</div>
			
			<!-- Save Progress Display -->
			{#if saveProgress.active}
				<div class="save-progress">
					<div class="progress-message">
						<div class="loader-spinner"></div>
						{saveProgress.message}
					</div>
				</div>
			{/if}
			
			<div class="form-content" class:disabled={saveProgress.active}>
				{#if !selectedUser}
					<div class="form-placeholder">
						Select a user from the list to manage their permissions.
					</div>
				{:else}
					<!-- Username display -->
					<div class="form-field">
						<label>Username</label>
						<input 
							type="text" 
							value={selectedUser}
							disabled={true}
							class="disabled-input"
						/>
					</div>
					
					<!-- Add new permission form -->
					<div class="permission-form">
						<h3>Add New Permission</h3>
						
						<div class="form-field">
							<label for="callLetters">Call Letters</label>
							<div class="call-letters-group">
								<input 
									id="callLetters"
									type="text" 
									value={newPermission.callLetters}
									disabled={saveProgress.active}
									placeholder="Enter call letters"
									on:keydown={(e) => e.key === 'Enter' && addPermission()}
									on:input={(e) => {
										// Force uppercase
										const target = e.target as HTMLInputElement;
										newPermission.callLetters = target.value.toUpperCase();
									}}
								/>
								<select 
									bind:value={newPermission.frequency}
									disabled={saveProgress.active}
								>
									<option value="FM">FM</option>
									<option value="AM">AM</option>
								</select>
							</div>
						</div>
						
						<div class="form-field">
							<label>Permission</label>
							<div class="checkbox-group">
								<label class="checkbox-label">
									<input 
										type="checkbox" 
										bind:checked={newPermission.canReceive}
										disabled={saveProgress.active}
									/>
									Receive
								</label>
								<label class="checkbox-label">
									<input 
										type="checkbox" 
										bind:checked={newPermission.canSend}
										disabled={saveProgress.active}
									/>
									Send
								</label>
							</div>
						</div>
						
						<button 
							class="form-btn add-btn" 
							on:click={addPermission}
							disabled={saveProgress.active}
						>
							Add Permission
						</button>
					</div>
					
					<!-- Existing permissions list -->
					<div class="permissions-list">
						<h3>Current Permissions</h3>
						
						{#if userAcls.length === 0}
							<div class="empty-permissions">
								No permissions configured for this user.
							</div>
						{:else}
							{#each userAcls as acl, index}
								{@const callLettersInfo = getCallLettersFromTopic(acl.topic)}
								<div class="permission-item">
									<div class="permission-info">
										<div class="call-letters">{callLettersInfo.callLetters} {callLettersInfo.frequency}</div>
										<div class="permission-type">{formatPermission(acl.action)}</div>
									</div>
									<button 
										class="remove-btn"
										on:click={() => removePermission(index)}
										disabled={saveProgress.active}
										title="Remove permission"
									>
										×
									</button>
								</div>
							{/each}
							
							<button 
								class="form-btn save-btn" 
								on:click={saveAcls}
								disabled={saveProgress.active || userAcls.length === 0}
							>
								Save All Permissions
							</button>
						{/if}
					</div>
				{/if}
			</div>
		</div>
	</div>
</div>

<style>
.dashboard-title {
	font-size: 2rem;
	font-weight: 700;
	color: #e5e7eb;
	margin-bottom: 0.5rem;
	letter-spacing: -0.5px;
}

.dashboard-error {
	color: #f87171;
	text-align: center;
	font-size: 1rem;
	margin-bottom: 1rem;
	padding: 0.75rem;
	background: rgba(248, 113, 113, 0.1);
	border-radius: 0.4rem;
	border: 1px solid rgba(248, 113, 113, 0.3);
}

.acl-management-container {
	display: flex;
	gap: 2rem;
	align-items: flex-start;
}

/* Left side - User list section */
.user-list-section {
	flex: 0 0 300px;
}

.list-box {
	background: #2d2d2d;
	border-radius: 0.5rem;
	box-shadow: 0 2px 8px rgba(0,0,0,0.15);
	overflow: hidden;
	border: 1px solid #404040;
}

.list-header {
	background: #404040;
	color: #3b82f6;
	font-size: 1.1rem;
	font-weight: 600;
	padding: 1rem 1.5rem;
	border-bottom: 1px solid #525252;
}

.list-content {
	max-height: 400px;
	overflow-y: auto;
}

.list-item {
	padding: 0.75rem 1.5rem;
	cursor: pointer;
	transition: background 0.15s;
	color: #e5e7eb;
	border-bottom: 1px solid #404040;
	font-size: 1rem;
}

.list-item:last-child {
	border-bottom: none;
}

.list-item:hover {
	background: #404040;
}

.list-item.selected {
	background: #1e40af;
	color: #fff;
}

.list-item:focus {
	outline: 2px solid #3b82f6;
	outline-offset: -2px;
}

.loading-item, .empty-item {
	padding: 0.75rem 1.5rem;
	color: #9ca3af;
	font-style: italic;
	text-align: center;
}

/* Right side - ACL section */
.acl-section {
	flex: 1;
}

.form-group-box {
	background: #2d2d2d;
	border-radius: 0.5rem;
	box-shadow: 0 2px 8px rgba(0,0,0,0.15);
	overflow: hidden;
	border: 1px solid #404040;
}

.form-header {
	background: #404040;
	color: #3b82f6;
	font-size: 1.1rem;
	font-weight: 600;
	padding: 1rem 1.5rem;
	border-bottom: 1px solid #525252;
}

.form-content {
	padding: 1.5rem;
}

.form-placeholder {
	color: #9ca3af;
	text-align: center;
	padding: 2rem;
	font-style: italic;
}

.form-field {
	margin-bottom: 1.5rem;
}

.form-field label {
	display: block;
	margin-bottom: 0.5rem;
	color: #e5e7eb;
	font-weight: 600;
	font-size: 1rem;
}

.form-field input {
	width: 100%;
	padding: 0.75rem 1rem;
	border: 1px solid #404040;
	border-radius: 0.4rem;
	font-size: 1rem;
	background: #1a1a1a;
	color: #e5e7eb;
	transition: border-color 0.15s, background 0.15s;
}

.form-field input:focus {
	border-color: #3b82f6;
	background: #2d2d2d;
	outline: none;
}

.form-field input:disabled {
	opacity: 0.6;
	cursor: not-allowed;
}

.disabled-input {
	background: #404040 !important;
	color: #9ca3af !important;
	cursor: not-allowed;
}

.call-letters-group {
	display: flex;
	gap: 0.5rem;
	align-items: stretch;
}

.call-letters-group input {
	flex: 1;
}

.call-letters-group select {
	padding: 0.75rem 1rem;
	border: 1px solid #404040;
	border-radius: 0.4rem;
	font-size: 1rem;
	background: #1a1a1a;
	color: #e5e7eb;
	transition: border-color 0.15s, background 0.15s;
	cursor: pointer;
}

.call-letters-group select:focus {
	border-color: #3b82f6;
	background: #2d2d2d;
	outline: none;
}

.call-letters-group select:disabled {
	opacity: 0.6;
	cursor: not-allowed;
}

/* Checkbox styles */
.checkbox-group {
	display: flex;
	gap: 1.5rem;
}

.checkbox-label {
	display: flex;
	align-items: center;
	gap: 0.5rem;
	cursor: pointer;
	color: #e5e7eb;
	font-size: 1rem;
}

.checkbox-label input[type="checkbox"] {
	width: 20px;
	height: 20px;
	margin: 0;
	cursor: pointer;
	accent-color: #3b82f6;
	background: #1a1a1a;
	border: 2px solid #404040;
	border-radius: 0.25rem;
}

.checkbox-label input[type="checkbox"]:checked {
	background: #3b82f6;
	border-color: #3b82f6;
}

.checkbox-label input[type="checkbox"]:focus {
	outline: 2px solid #3b82f6;
	outline-offset: 2px;
}

.checkbox-label:hover input[type="checkbox"] {
	border-color: #3b82f6;
}

/* Permission form section */
.permission-form {
	background: #1a1a1a;
	border-radius: 0.4rem;
	padding: 1.5rem;
	margin-bottom: 2rem;
	border: 1px solid #404040;
}

.permission-form h3 {
	color: #3b82f6;
	font-size: 1.1rem;
	font-weight: 600;
	margin-bottom: 1rem;
	margin-top: 0;
}

/* Permissions list section */
.permissions-list {
	background: #1a1a1a;
	border-radius: 0.4rem;
	padding: 1.5rem;
	border: 1px solid #404040;
}

.permissions-list h3 {
	color: #3b82f6;
	font-size: 1.1rem;
	font-weight: 600;
	margin-bottom: 1rem;
	margin-top: 0;
}

.empty-permissions {
	color: #9ca3af;
	text-align: center;
	padding: 2rem;
	font-style: italic;
}

.permission-item {
	display: flex;
	align-items: center;
	justify-content: space-between;
	padding: 1rem;
	background: #2d2d2d;
	border-radius: 0.4rem;
	margin-bottom: 0.75rem;
	border: 1px solid #404040;
}

.permission-info {
	display: flex;
	align-items: center;
	gap: 1rem;
}

.call-letters {
	font-weight: 600;
	color: #e5e7eb;
	font-size: 1rem;
}

.permission-type {
	color: #3b82f6;
	font-size: 0.9rem;
	background: rgba(59, 130, 246, 0.1);
	padding: 0.25rem 0.75rem;
	border-radius: 1rem;
	border: 1px solid rgba(59, 130, 246, 0.3);
}

.remove-btn {
	background: #dc2626;
	color: white;
	border: none;
	border-radius: 50%;
	width: 32px;
	height: 32px;
	font-size: 1.2rem;
	font-weight: bold;
	cursor: pointer;
	transition: background 0.15s;
	display: flex;
	align-items: center;
	justify-content: center;
}

.remove-btn:hover:not(:disabled) {
	background: #b91c1c;
}

.remove-btn:disabled {
	opacity: 0.5;
	cursor: not-allowed;
}

/* Button styles */
.form-btn {
	padding: 0.75rem 1.5rem;
	border: none;
	border-radius: 0.4rem;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
	transition: background 0.15s;
	width: 100%;
}

.form-btn:disabled {
	opacity: 0.5;
	cursor: not-allowed;
}

.add-btn {
	background: #059669;
	color: white;
}

.add-btn:hover:not(:disabled) {
	background: #047857;
}

.save-btn {
	background: #2563eb;
	color: white;
	margin-top: 1rem;
}

.save-btn:hover:not(:disabled) {
	background: #1d4ed8;
}

/* Save Progress styles */
.save-progress {
	background: #1e40af;
	border-radius: 0.4rem;
	padding: 1rem;
	margin-bottom: 1rem;
	border: 1px solid #3b82f6;
}

.progress-message {
	display: flex;
	align-items: center;
	gap: 0.75rem;
	color: white;
	font-size: 0.95rem;
	font-weight: 500;
}

.loader-spinner {
	width: 20px;
	height: 20px;
	border: 2px solid rgba(255, 255, 255, 0.3);
	border-top: 2px solid white;
	border-radius: 50%;
	animation: spin 1s linear infinite;
	flex-shrink: 0;
}

@keyframes spin {
	0% { transform: rotate(0deg); }
	100% { transform: rotate(360deg); }
}

/* Disabled form content */
.form-content.disabled {
	opacity: 0.6;
	pointer-events: none;
}

.form-content.disabled .form-field input,
.form-content.disabled .form-actions button {
	cursor: not-allowed;
}

/* Responsive design */
@media (max-width: 768px) {
	.acl-management-container {
		flex-direction: column;
		gap: 1rem;
	}
	
	.user-list-section {
		flex: none;
		width: 100%;
	}
	
	.checkbox-group {
		flex-direction: column;
		gap: 1rem;
	}
}
</style> 