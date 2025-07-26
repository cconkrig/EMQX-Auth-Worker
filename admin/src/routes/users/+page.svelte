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
		
		const res = await fetch('/admin/api/users', {
			headers: { Authorization: `Bearer ${token}` }
		});
		
		if (!res.ok) {
			const errorText = await res.text();
			throw new Error(`Failed to load users: ${res.status} ${errorText}`);
		}
		
		const data = await res.json();
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
		
		if (formMode === 'add') {
			// Add new user
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
		}
		
		await loadUsers();
		cancelForm();
	} catch (e: any) {
		console.error('Save user error:', e);
		dashboardError = e.message || 'Failed to save user';
	} finally {
		dashboardLoading = false;
	}
}

function confirmDeleteUser(user: string) {
	userToDelete = user;
	showDeleteConfirm = true;
}

async function deleteUser() {
	if (!userToDelete) return;
	
	dashboardError = '';
	dashboardLoading = true;
	
	try {
		const token = getToken();
		if (!token) {
			throw new Error('No authentication token found');
		}
		
		// Reset session timeout for API activity
		if (typeof window !== 'undefined' && (window as any).resetSessionTimeout) {
			(window as any).resetSessionTimeout();
		}
		
		const res = await fetch('/admin/api/user', {
			method: 'DELETE',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${token}`
			},
			body: JSON.stringify({ username: userToDelete })
		});
		
		if (!res.ok) throw new Error('Failed to delete user');
		
		await loadUsers();
		if (selectedUser === userToDelete) {
			selectedUser = null;
			formMode = 'none';
			formEnabled = false;
			clearForm();
		}
	} catch (e: any) {
		dashboardError = e.message || 'Failed to delete user';
	} finally {
		dashboardLoading = false;
		showDeleteConfirm = false;
		userToDelete = null;
	}
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
				disabled={formMode !== 'none'}
			>
				Add
			</button>
			<button 
				class="action-btn edit-btn" 
				on:click={enableEditMode}
				disabled={!selectedUser || formMode !== 'none'}
			>
				Edit
			</button>
			<button 
				class="action-btn delete-btn" 
				on:click={() => confirmDeleteUser(selectedUser!)}
				disabled={!selectedUser || formMode !== 'none'}
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
			
			<div class="form-content">
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
							disabled={!formEnabled}
							placeholder="Enter username"
						/>
					</div>
					
					<div class="form-field">
						<label for="password">Password</label>
						<input 
							id="password"
							type="password" 
							bind:value={formData.password}
							disabled={!formEnabled}
							placeholder="Enter password"
						/>
					</div>
					
					<div class="form-actions">
						<button 
							class="form-btn save-btn" 
							on:click={saveUser}
							disabled={!formEnabled || dashboardLoading}
						>
							Save
						</button>
						<button 
							class="form-btn cancel-btn" 
							on:click={cancelForm}
							disabled={!formEnabled || dashboardLoading}
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
	<div class="modal-overlay" on:click={cancelDelete}>
		<div class="modal-content" on:click|stopPropagation>
			<div class="modal-header">Confirm Delete</div>
			<div class="modal-body">
				<p>Are you sure you want to delete user <strong>{userToDelete}</strong>?</p>
				<p class="warning-text">⚠️ This will also remove all ACLs associated with this user.</p>
			</div>
			<div class="modal-actions">
				<button class="modal-btn cancel-btn" on:click={cancelDelete}>Cancel</button>
				<button class="modal-btn delete-btn" on:click={deleteUser} disabled={dashboardLoading}>
					{dashboardLoading ? 'Deleting...' : 'Delete'}
				</button>
			</div>
		</div>
	</div>
{/if}

<style>
.dashboard-title {
	font-size: 2.3rem;
	font-weight: 800;
	color: #e5e7eb;
	margin-bottom: 0.5rem;
	letter-spacing: -1px;
}

.dashboard-error {
	color: #f87171;
	text-align: center;
	font-size: 1.1rem;
	margin-bottom: 1rem;
	padding: 0.75rem;
	background: rgba(248, 113, 113, 0.1);
	border-radius: 0.5rem;
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
	background: #23283a;
	border-radius: 1.2rem;
	box-shadow: 0 2px 8px rgba(0,0,0,0.10);
	overflow: hidden;
	margin-bottom: 1rem;
}

.list-header {
	background: #1e293b;
	color: #60a5fa;
	font-size: 1.15rem;
	font-weight: 700;
	padding: 1rem 1.5rem;
	border-bottom: 1px solid #334155;
}

.list-content {
	max-height: 400px;
	overflow-y: auto;
}

.list-item {
	padding: 0.75rem 1.5rem;
	cursor: pointer;
	transition: background 0.2s;
	color: #e5e7eb;
	border-bottom: 1px solid #334155;
	font-size: 1rem;
}

.list-item:last-child {
	border-bottom: none;
}

.list-item:hover {
	background: #1e293b;
}

.list-item.selected {
	background: #2563eb;
	color: #fff;
}

.list-item:focus {
	outline: 2px solid #60a5fa;
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
	border-radius: 0.7rem;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
	transition: all 0.2s;
}

.action-btn:disabled {
	opacity: 0.5;
	cursor: not-allowed;
}

.add-btn {
	background: linear-gradient(90deg, #059669 60%, #10b981 100%);
	color: white;
}

.add-btn:hover:not(:disabled) {
	background: linear-gradient(90deg, #047857 60%, #059669 100%);
	transform: translateY(-1px);
}

.edit-btn {
	background: linear-gradient(90deg, #2563eb 60%, #60a5fa 100%);
	color: white;
}

.edit-btn:hover:not(:disabled) {
	background: linear-gradient(90deg, #1d4ed8 60%, #2563eb 100%);
	transform: translateY(-1px);
}

.delete-btn {
	background: linear-gradient(90deg, #dc2626 60%, #ef4444 100%);
	color: white;
}

.delete-btn:hover:not(:disabled) {
	background: linear-gradient(90deg, #b91c1c 60%, #dc2626 100%);
	transform: translateY(-1px);
}

/* Right side - Form section */
.form-section {
	flex: 1;
}

.form-group-box {
	background: #23283a;
	border-radius: 1.2rem;
	box-shadow: 0 2px 8px rgba(0,0,0,0.10);
	overflow: hidden;
}

.form-header {
	background: #1e293b;
	color: #60a5fa;
	font-size: 1.15rem;
	font-weight: 700;
	padding: 1rem 1.5rem;
	border-bottom: 1px solid #334155;
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
	border: 1.5px solid #334155;
	border-radius: 0.7rem;
	font-size: 1rem;
	background: #181c24;
	color: #e5e7eb;
	transition: border-color 0.2s, background 0.2s;
}

.form-field input:focus {
	border-color: #60a5fa;
	background: #23283a;
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
	border-radius: 0.7rem;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
	transition: all 0.2s;
}

.form-btn:disabled {
	opacity: 0.5;
	cursor: not-allowed;
}

.save-btn {
	background: linear-gradient(90deg, #059669 60%, #10b981 100%);
	color: white;
}

.save-btn:hover:not(:disabled) {
	background: linear-gradient(90deg, #047857 60%, #059669 100%);
	transform: translateY(-1px);
}

.cancel-btn {
	background: linear-gradient(90deg, #f59e0b 60%, #fbbf24 100%);
	color: white;
}

.cancel-btn:hover:not(:disabled) {
	background: linear-gradient(90deg, #d97706 60%, #f59e0b 100%);
	transform: translateY(-1px);
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
	background: #23283a;
	border-radius: 1.2rem;
	box-shadow: 0 4px 20px rgba(0,0,0,0.3);
	max-width: 500px;
	width: 90%;
	margin: 1rem;
}

.modal-header {
	background: #1e293b;
	color: #60a5fa;
	font-size: 1.2rem;
	font-weight: 700;
	padding: 1rem 1.5rem;
	border-bottom: 1px solid #334155;
	border-radius: 1.2rem 1.2rem 0 0;
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
	color: #fbbf24;
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
	border-radius: 0.7rem;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
	transition: all 0.2s;
}

.modal-btn:disabled {
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