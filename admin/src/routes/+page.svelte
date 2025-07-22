<script lang="ts">
	import { onMount } from 'svelte';

	// Auth state
	let username = '';
	let password = '';
	let error = '';
	let loading = false;
	let token: string | null = null;
	let isLoggedIn = false;

	// Dashboard state
	let users: string[] = [];
	let selectedUser: string | null = null;
	let userAcls: any[] = [];
	let newUser = { username: '', password: '', acls: '' };
	let dashboardError = '';
	let dashboardLoading = false;
	let userAclsString = '';

	function getToken() {
		return localStorage.getItem('admin_token');
	}

	onMount(() => {
		token = getToken();
		isLoggedIn = !!token;
		if (isLoggedIn) {
			loadUsers();
		}
	});

	async function login() {
		error = '';
		loading = true;
		try {
			const res = await fetch('/admin/api/login', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ username, password })
			});
			if (!res.ok) {
				const data = await res.json().catch(() => ({}));
				throw new Error(data.error || 'Login failed');
			}
			const { token: t } = await res.json();
			localStorage.setItem('admin_token', t);
			token = t;
			isLoggedIn = true;
			await loadUsers();
		} catch (e: any) {
			error = e.message || 'Login failed';
		} finally {
			loading = false;
		}
	}

	function logout() {
		localStorage.removeItem('admin_token');
		token = null;
		isLoggedIn = false;
		selectedUser = null;
		users = [];
	}

	async function loadUsers() {
		dashboardLoading = true;
		dashboardError = '';
		try {
			const res = await fetch('/admin/api/users', {
				headers: { Authorization: `Bearer ${token}` }
			});
			if (!res.ok) throw new Error('Failed to load users');
			const data = await res.json();
			users = data.users || [];
		} catch (e: any) {
			dashboardError = e.message || 'Failed to load users';
		} finally {
			dashboardLoading = false;
		}
	}

	async function selectUser(user: string) {
		selectedUser = user;
		userAcls = [];
		dashboardError = '';
		try {
			const res = await fetch(`/admin/api/user-details?username=${encodeURIComponent(user)}`, {
				headers: { Authorization: `Bearer ${token}` }
			});
			if (!res.ok) throw new Error('Failed to load user details');
			const data = await res.json();
			userAcls = data.acls || [];
			userAclsString = JSON.stringify(userAcls, null, 2);
		} catch (e: any) {
			dashboardError = e.message || 'Failed to load user details';
		}
	}

	async function addUser() {
		dashboardError = '';
		if (!newUser.username || !newUser.password) {
			dashboardError = 'Username and password required';
			return;
		}
		dashboardLoading = true;
		try {
			const res = await fetch('/admin/api/user', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${token}`
				},
				body: JSON.stringify({
					username: newUser.username,
					password: newUser.password,
					acls: newUser.acls ? JSON.parse(newUser.acls) : []
				})
			});
			if (!res.ok) throw new Error('Failed to add user');
			await loadUsers();
			newUser = { username: '', password: '', acls: '' };
		} catch (e: any) {
			dashboardError = e.message || 'Failed to add user';
		} finally {
			dashboardLoading = false;
		}
	}

	async function deleteUser(user: string) {
		dashboardError = '';
		dashboardLoading = true;
		try {
			const res = await fetch('/admin/api/user', {
				method: 'DELETE',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${token}`
				},
				body: JSON.stringify({ username: user })
			});
			if (!res.ok) throw new Error('Failed to delete user');
			await loadUsers();
			if (selectedUser === user) selectedUser = null;
		} catch (e: any) {
			dashboardError = e.message || 'Failed to delete user';
		} finally {
			dashboardLoading = false;
		}
	}

	async function updateAcls() {
		dashboardError = '';
		dashboardLoading = true;
		try {
			let parsed;
			try {
				parsed = JSON.parse(userAclsString);
			} catch {
				throw new Error('Invalid JSON in ACLs');
			}
			const res = await fetch('/admin/api/acl', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${token}`
				},
				body: JSON.stringify({ username: selectedUser, acls: parsed })
			});
			if (!res.ok) throw new Error('Failed to update ACLs');
			userAcls = parsed;
		} catch (e: any) {
			dashboardError = e.message || 'Failed to update ACLs';
		} finally {
			dashboardLoading = false;
		}
	}
</script>

<style>
.login-container {
	display: flex;
	flex-direction: column;
	align-items: center;
	justify-content: center;
	height: 100vh;
	background: linear-gradient(135deg, #f8fafc 0%, #e0e7ef 100%);
}
.login-box {
	background: white;
	padding: 2.5rem 2rem;
	border-radius: 1.25rem;
	box-shadow: 0 4px 32px rgba(0,0,0,0.08);
	width: 100%;
	max-width: 350px;
	display: flex;
	flex-direction: column;
	gap: 1.25rem;
}
.login-title {
	font-size: 2rem;
	font-weight: 700;
	color: #1e293b;
	text-align: center;
}
.input-group {
	display: flex;
	flex-direction: column;
	gap: 0.5rem;
}
input[type="text"], input[type="password"] {
	padding: 0.75rem 1rem;
	border: 1px solid #cbd5e1;
	border-radius: 0.5rem;
	font-size: 1rem;
	outline: none;
	transition: border 0.2s;
}
input:focus {
	border-color: #2563eb;
}
.login-btn {
	background: #2563eb;
	color: white;
	padding: 0.75rem 1rem;
	border: none;
	border-radius: 0.5rem;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
	transition: background 0.2s;
}
.login-btn:disabled {
	background: #93c5fd;
	cursor: not-allowed;
}
.error {
	color: #dc2626;
	text-align: center;
	font-size: 1rem;
}
.dashboard-container {
	display: flex;
	flex-direction: column;
	align-items: center;
	justify-content: flex-start;
	min-height: 100vh;
	background: linear-gradient(135deg, #f8fafc 0%, #e0e7ef 100%);
	padding: 2rem 0;
}
.dashboard-box {
	background: white;
	padding: 2rem 2.5rem;
	border-radius: 1.25rem;
	box-shadow: 0 4px 32px rgba(0,0,0,0.08);
	width: 100%;
	max-width: 700px;
	display: flex;
	flex-direction: column;
	gap: 2rem;
}
.dashboard-title {
	font-size: 2rem;
	font-weight: 700;
	color: #1e293b;
	text-align: center;
}
.user-list {
	display: flex;
	gap: 0.5rem;
	flex-wrap: wrap;
}
.user-item {
	background: #f1f5f9;
	padding: 0.5rem 1rem;
	border-radius: 0.5rem;
	margin-bottom: 0.5rem;
	display: flex;
	align-items: center;
	gap: 0.5rem;
	cursor: pointer;
	transition: background 0.2s;
}
.user-item.selected {
	background: #2563eb;
	color: white;
}
.delete-btn {
	background: #dc2626;
	color: white;
	border: none;
	border-radius: 0.25rem;
	padding: 0.25rem 0.5rem;
	cursor: pointer;
	font-size: 0.9rem;
}
.add-user-form {
	display: flex;
	gap: 0.5rem;
	flex-wrap: wrap;
	align-items: flex-end;
}
.add-user-form input {
	padding: 0.5rem 0.75rem;
	border: 1px solid #cbd5e1;
	border-radius: 0.5rem;
	font-size: 1rem;
}
.add-user-form button {
	background: #2563eb;
	color: white;
	padding: 0.5rem 1rem;
	border: none;
	border-radius: 0.5rem;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
}
.acl-editor {
	display: flex;
	flex-direction: column;
	gap: 0.5rem;
	margin-top: 1rem;
}
.acl-editor textarea {
	width: 100%;
	min-height: 80px;
	padding: 0.5rem;
	border: 1px solid #cbd5e1;
	border-radius: 0.5rem;
	font-size: 1rem;
}
.save-btn {
	background: #059669;
	color: white;
	padding: 0.5rem 1rem;
	border: none;
	border-radius: 0.5rem;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
	margin-top: 0.5rem;
}
.logout-btn {
	background: #64748b;
	color: white;
	padding: 0.5rem 1rem;
	border: none;
	border-radius: 0.5rem;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
	margin-top: 1rem;
}
.dashboard-error {
	color: #dc2626;
	text-align: center;
	font-size: 1rem;
	margin-bottom: 1rem;
}
</style>

{#if !isLoggedIn}
	<!-- Login Form -->
	<div class="login-container">
		<form class="login-box" on:submit|preventDefault={login}>
			<div class="login-title">Admin Login</div>
			<div class="input-group">
				<label for="username">Username</label>
				<input id="username" type="text" bind:value={username} autocomplete="username" required />
			</div>
			<div class="input-group">
				<label for="password">Password</label>
				<input id="password" type="password" bind:value={password} autocomplete="current-password" required />
			</div>
			{#if error}
				<div class="error">{error}</div>
			{/if}
			<button class="login-btn" type="submit" disabled={loading}>{loading ? 'Logging in…' : 'Login'}</button>
		</form>
	</div>
{:else}
	<!-- Dashboard -->
	<div class="dashboard-container">
		<div class="dashboard-box">
			<div class="dashboard-title">Admin Dashboard</div>
			{#if dashboardError}
				<div class="dashboard-error">{dashboardError}</div>
			{/if}
			<div>
				<strong>Users:</strong>
				<div class="user-list">
					{#each users as user}
						<div class="user-item {selectedUser === user ? 'selected' : ''}" on:click={() => selectUser(user)}>
							{user}
							<button class="delete-btn" on:click|stopPropagation={() => deleteUser(user)} title="Delete user">✕</button>
						</div>
					{/each}
				</div>
			</div>
			<form class="add-user-form" on:submit|preventDefault={addUser}>
				<input type="text" placeholder="New username" bind:value={newUser.username} required />
				<input type="password" placeholder="Password" bind:value={newUser.password} required />
				<input type="text" placeholder='ACLs (JSON array)' bind:value={newUser.acls} />
				<button type="submit" disabled={dashboardLoading}>Add User</button>
			</form>
			{#if selectedUser}
				<div>
					<strong>ACLs for {selectedUser}:</strong>
					<div class="acl-editor">
						<textarea bind:value={userAclsString} />
						<button class="save-btn" on:click={updateAcls} disabled={dashboardLoading}>Save ACLs</button>
					</div>
				</div>
			{/if}
			<button class="logout-btn" on:click={logout}>Logout</button>
		</div>
	</div>
{/if}
