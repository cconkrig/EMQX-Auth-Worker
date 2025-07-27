<script lang="ts">
import { onMount } from 'svelte';

// Data state
let users: string[] = [];
let selectedUser: string | null = null;
let userAcls: any[] = [];
let dashboardError = '';
let dashboardLoading = false;

// Form state
let formMode: 'none' | 'add' | 'edit' = 'none';
let formData = { username: '', password: '' };
let formEnabled = false;

// Confirmation state
let showDeleteConfirm = false;
let userToDelete: string | null = null;

// Save progress state
let saveProgress = {
	active: false,
	message: '',
	retryCount: 0,
	maxRetries: 5
};

// Delete progress state
let deleteProgress = {
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
	formMode = 'none';
	formEnabled = false;
	clearForm();
	
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

function clearForm() {
	formData = { username: '', password: '' };
}

function enableAddMode() {
	formMode = 'add';
	formEnabled = true;
	clearForm();
	selectedUser = null;
}

function enableEditMode() {
	if (!selectedUser) return;
	formMode = 'edit';
	formEnabled = true;
	formData.username = selectedUser;
	formData.password = ''; // Never load password
}

function cancelForm() {
	formMode = 'none';
	formEnabled = false;
	clearForm();
}

async function saveUser() {
	if (!formData.username || !formData.password) {
		dashboardError = 'Username and password required';
		return;
	}
	
	// Start save progress
	saveProgress = {
		active: true,
		message: 'Saving user... this may take a moment while it propagates to the network...',
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
			
			if (formMode === 'add') {
				// Add new user
				console.log('Adding user:', formData.username);
				const res = await fetch('/admin/api/user', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						Authorization: `Bearer ${token}`
					},
					body: JSON.stringify({
						username: formData.username,
						password: formData.password,
						acls: []
					})
				});
				
				if (!res.ok) {
					const errorText = await res.text();
					throw new Error(`Failed to add user: ${res.status} ${errorText}`);
				}
				
				console.log('User added successfully');
				
				// For add mode, implement a more robust retry mechanism
				const retryDelay = 5000; // 5 seconds as requested
				
				while (saveProgress.retryCount < saveProgress.maxRetries && !users.includes(formData.username)) {
					saveProgress.retryCount++;
					saveProgress.message = `Saving user... this may take a moment while it propagates to the network... (Attempt ${saveProgress.retryCount}/${saveProgress.maxRetries})`;
					
					console.log(`Retry ${saveProgress.retryCount}/${saveProgress.maxRetries} - waiting ${retryDelay}ms...`);
					await new Promise(resolve => setTimeout(resolve, retryDelay));
					await loadUsers();
				}
				
				if (!users.includes(formData.username)) {
					console.warn('User still not found after all retries, but operation was successful');
				} else {
					console.log('User found in list after retry');
				}
			} else if (formMode === 'edit' && selectedUser) {
				// Update existing user
				const res = await fetch('/admin/api/user', {
					method: 'PUT',
					headers: {
						'Content-Type': 'application/json',
						Authorization: `Bearer ${token}`
					},
					body: JSON.stringify({
						username: selectedUser,
						newUsername: formData.username,
						password: formData.password
					})
				});
				
				if (!res.ok) {
					const errorText = await res.text();
					throw new Error(`Failed to update user: ${res.status} ${errorText}`);
				}
				
				console.log('User updated successfully');
				
				// For edit mode, implement retry mechanism to check if username change is reflected
				const retryDelay = 5000; // 5 seconds as requested
				const originalUsername = selectedUser;
				const newUsername = formData.username;
				const usernameChanged = originalUsername !== newUsername;
				
				while (saveProgress.retryCount < saveProgress.maxRetries) {
					saveProgress.retryCount++;
					saveProgress.message = `Updating user... this may take a moment while it propagates to the network... (Attempt ${saveProgress.retryCount}/${saveProgress.maxRetries})`;
					
					console.log(`Retry ${saveProgress.retryCount}/${saveProgress.maxRetries} - waiting ${retryDelay}ms...`);
					await new Promise(resolve => setTimeout(resolve, retryDelay));
					await loadUsers();
					
					// Check if the update was successful
					if (usernameChanged) {
						// If username changed, check if new username exists and old one doesn't
						if (users.includes(newUsername) && !users.includes(originalUsername)) {
							console.log('Username change confirmed in list');
							break;
						}
					} else {
						// If username didn't change, just check if user still exists
						if (users.includes(originalUsername)) {
							console.log('User update confirmed in list');
							break;
						}
					}
				}
				
				if (usernameChanged && (!users.includes(newUsername) || users.includes(originalUsername))) {
					console.warn('Username change not fully reflected after all retries, but operation was successful');
				} else if (!usernameChanged && !users.includes(originalUsername)) {
					console.warn('User not found after update, but operation was successful');
				} else {
					console.log('User update confirmed after retry');
				}
			}
			
			cancelForm();
		} catch (e: any) {
			console.error('Save user error:', e);
			dashboardError = e.message || 'Failed to save user';
		} finally {
			saveProgress.active = false;
		}
	}, 0);
}

function confirmDeleteUser(user: string) {
	if (!user) {
		console.error('Cannot confirm delete: user parameter is null or empty');
		dashboardError = 'Cannot delete user: invalid user selection';
		return;
	}
	console.log('Confirming delete for user:', user);
	userToDelete = user;
	showDeleteConfirm = true;
	console.log('userToDelete set to:', userToDelete);
}

async function deleteUser() {
	if (!userToDelete) {
		console.error('Cannot delete user: userToDelete is null');
		dashboardError = 'Cannot delete user: no user selected';
		return;
	}
	
	// Capture the username immediately to avoid closure issues
	const usernameToDelete = userToDelete;
	console.log('Starting delete process for user:', usernameToDelete);
	
	// Start delete progress
	deleteProgress = {
		active: true,
		message: 'Deleting user... this may take a moment while it propagates to the network...',
		retryCount: 0,
		maxRetries: 5
	};
	dashboardError = '';
	
	// Run the delete operation in the background
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
			
			console.log('Deleting user:', usernameToDelete);
			const res = await fetch('/admin/api/user', {
				method: 'DELETE',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${token}`
				},
				body: JSON.stringify({ username: usernameToDelete })
			});
			
			if (!res.ok) {
				const errorText = await res.text();
				throw new Error(`Failed to delete user: ${res.status} ${errorText}`);
			}
			
			console.log('User deleted successfully');
			
			// Implement retry mechanism to confirm user is removed from list
			const retryDelay = 5000; // 5 seconds as requested
			
			while (deleteProgress.retryCount < deleteProgress.maxRetries && users.includes(usernameToDelete)) {
				deleteProgress.retryCount++;
				deleteProgress.message = `Deleting user... this may take a moment while it propagates to the network... (Attempt ${deleteProgress.retryCount}/${deleteProgress.maxRetries})`;
				
				console.log(`Retry ${deleteProgress.retryCount}/${deleteProgress.maxRetries} - waiting ${retryDelay}ms...`);
				await new Promise(resolve => setTimeout(resolve, retryDelay));
				await loadUsers();
			}
			
			if (users.includes(usernameToDelete)) {
				console.warn('User still found in list after all retries, but operation was successful');
			} else {
				console.log('User confirmed removed from list after retry');
			}
			
			// Clean up selection if deleted user was selected
			if (selectedUser === usernameToDelete) {
				selectedUser = null;
				formMode = 'none';
				formEnabled = false;
				clearForm();
			}
			
		} catch (e: any) {
			console.error('Delete user error:', e);
			dashboardError = e.message || 'Failed to delete user';
		} finally {
			deleteProgress.active = false;
			showDeleteConfirm = false;
			userToDelete = null;
		}
	}, 0);
}

function cancelDelete() {
	showDeleteConfirm = false;
	userToDelete = null;
}
</script>

<div class="dashboard-title">User Management</div>

{#if dashboardError}
	<div class="dashboard-error">{dashboardError}</div>
{/if}

<div class="user-management-container">
	<!-- Left side: User list and action buttons -->
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
		
		<div class="action-buttons">
			<button 
				class="action-btn add-btn" 
				on:click={enableAddMode}
				disabled={formMode !== 'none' || saveProgress.active || deleteProgress.active}
			>
				Add
			</button>
			<button 
				class="action-btn edit-btn" 
				on:click={enableEditMode}
				disabled={!selectedUser || formMode !== 'none' || saveProgress.active || deleteProgress.active}
			>
				Edit
			</button>
			<button 
				class="action-btn delete-btn" 
				on:click={() => selectedUser && confirmDeleteUser(selectedUser)}
				disabled={!selectedUser || formMode !== 'none' || saveProgress.active || deleteProgress.active}
			>
				Delete
			</button>
		</div>
	</div>

	<!-- Right side: Form group box -->
	<div class="form-section">
		<div class="form-group-box">
			<div class="form-header">
				{#if formMode === 'add'}
					Add New User
				{:else if formMode === 'edit'}
					Edit User
				{:else}
					User Details
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
			
			<!-- Delete Progress Display -->
			{#if deleteProgress.active}
				<div class="delete-progress">
					<div class="progress-message">
						<div class="loader-spinner"></div>
						{deleteProgress.message}
					</div>
				</div>
			{/if}
			
			<div class="form-content" class:disabled={saveProgress.active || deleteProgress.active}>
				{#if formMode === 'none'}
					<div class="form-placeholder">
						Select a user from the list or click "Add" to create a new user.
					</div>
				{:else}
					<div class="form-field">
						<label for="username">Username</label>
						<input 
							id="username"
							type="text" 
							bind:value={formData.username}
							disabled={!formEnabled || saveProgress.active || deleteProgress.active}
							placeholder="Enter username"
						/>
					</div>
					
					<div class="form-field">
						<label for="password">Password</label>
						<input 
							id="password"
							type="password" 
							bind:value={formData.password}
							disabled={!formEnabled || saveProgress.active || deleteProgress.active}
							placeholder="Enter password"
						/>
					</div>
					
					<div class="form-actions">
						<button 
							class="form-btn save-btn" 
							on:click={saveUser}
							disabled={!formEnabled || saveProgress.active || deleteProgress.active}
						>
							Save
						</button>
						<button 
							class="form-btn cancel-btn" 
							on:click={cancelForm}
							disabled={!formEnabled || saveProgress.active || deleteProgress.active}
						>
							Cancel
						</button>
					</div>
				{/if}
			</div>
		</div>
	</div>
</div>

<!-- Delete confirmation modal -->
{#if showDeleteConfirm}
	<div 
		class="modal-overlay" 
		on:click={cancelDelete}
		on:keydown={(e) => e.key === 'Escape' && cancelDelete()}
		role="dialog"
		aria-modal="true"
		aria-labelledby="modal-title"
		tabindex="-1"
	>
		<div 
			class="modal-content" 
			role="document"
		>
			<div class="modal-header" id="modal-title">Confirm Delete</div>
			<div class="modal-body">
				<p>Are you sure you want to delete user <strong>{userToDelete}</strong>?</p>
				<p class="warning-text">⚠️ This will also remove all ACLs associated with this user.</p>
				
				{#if deleteProgress.active}
					<div class="modal-progress">
						<div class="progress-message">
							<div class="loader-spinner"></div>
							{deleteProgress.message}
						</div>
					</div>
				{/if}
			</div>
			<div class="modal-actions">
				<button class="modal-btn cancel-btn" on:click={cancelDelete} disabled={deleteProgress.active}>Cancel</button>
				<button class="modal-btn delete-btn" on:click={deleteUser} disabled={deleteProgress.active}>
					{deleteProgress.active ? 'Deleting...' : 'Delete'}
				</button>
			</div>
		</div>
	</div>
{/if}

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

.user-management-container {
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
	margin-bottom: 1rem;
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

/* Action buttons */
.action-buttons {
	display: flex;
	gap: 0.5rem;
}

.action-btn {
	flex: 1;
	padding: 0.75rem 1rem;
	border: none;
	border-radius: 0.4rem;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
	transition: background 0.15s;
}

.action-btn:disabled {
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

.edit-btn {
	background: #2563eb;
	color: white;
}

.edit-btn:hover:not(:disabled) {
	background: #1d4ed8;
}

.delete-btn {
	background: #dc2626;
	color: white;
}

.delete-btn:hover:not(:disabled) {
	background: #b91c1c;
}

/* Right side - Form section */
.form-section {
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

.form-actions {
	display: flex;
	gap: 1rem;
	margin-top: 2rem;
}

.form-btn {
	flex: 1;
	padding: 0.75rem 1.5rem;
	border: none;
	border-radius: 0.4rem;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
	transition: background 0.15s;
}

.form-btn:disabled {
	opacity: 0.5;
	cursor: not-allowed;
}

.save-btn {
	background: #059669;
	color: white;
}

.save-btn:hover:not(:disabled) {
	background: #047857;
}

.cancel-btn {
	background: #f59e0b;
	color: white;
}

.cancel-btn:hover:not(:disabled) {
	background: #d97706;
}

/* Modal styles */
.modal-overlay {
	position: fixed;
	top: 0;
	left: 0;
	right: 0;
	bottom: 0;
	background: rgba(0, 0, 0, 0.7);
	display: flex;
	align-items: center;
	justify-content: center;
	z-index: 1000;
}

.modal-content {
	background: #2d2d2d;
	border-radius: 0.5rem;
	box-shadow: 0 4px 20px rgba(0,0,0,0.3);
	max-width: 500px;
	width: 90%;
	margin: 1rem;
	border: 1px solid #404040;
}

.modal-header {
	background: #404040;
	color: #3b82f6;
	font-size: 1.1rem;
	font-weight: 600;
	padding: 1rem 1.5rem;
	border-bottom: 1px solid #525252;
	border-radius: 0.5rem 0.5rem 0 0;
}

.modal-body {
	padding: 1.5rem;
	color: #e5e7eb;
}

.modal-body p {
	margin-bottom: 1rem;
	line-height: 1.5;
}

.warning-text {
	color: #f59e0b;
	font-weight: 600;
}

.modal-actions {
	display: flex;
	gap: 1rem;
	padding: 1rem 1.5rem 1.5rem;
}

.modal-btn {
	flex: 1;
	padding: 0.75rem 1.5rem;
	border: none;
	border-radius: 0.4rem;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
	transition: background 0.15s;
}

.modal-btn:disabled {
	opacity: 0.5;
	cursor: not-allowed;
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

/* Delete Progress styles */
.delete-progress {
	background: #dc2626;
	border-radius: 0.4rem;
	padding: 1rem;
	margin-bottom: 1rem;
	border: 1px solid #ef4444;
}

.delete-progress .progress-message {
	color: white;
}

/* Modal Progress styles */
.modal-progress {
	background: #1e40af;
	border-radius: 0.4rem;
	padding: 1rem;
	margin-bottom: 1rem;
	border: 1px solid #3b82f6;
}

.modal-progress .progress-message {
	color: white;
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

/* Disabled action buttons */
.action-btn:disabled {
	opacity: 0.5;
	cursor: not-allowed;
}

/* Responsive design */
@media (max-width: 768px) {
	.user-management-container {
		flex-direction: column;
		gap: 1rem;
	}
	
	.user-list-section {
		flex: none;
		width: 100%;
	}
	
	.action-buttons {
		flex-direction: column;
	}
	
	.form-actions {
		flex-direction: column;
	}
}
</style> 