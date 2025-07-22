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

	// ACL UI state
	let aclAction = 'publish';
	let aclTopic = '';
	let aclEditIndex: number | null = null;
	let aclEditAction = 'publish';
	let aclEditTopic = '';

	// Sidebar navigation state
	let nav = 'dashboard';
	function setNav(n: string) { nav = n; aclEditIndex = null; resetAclForm(); selectedUser = null; }

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

	function resetAclForm() {
		aclAction = 'publish';
		aclTopic = '';
		aclEditIndex = null;
		aclEditAction = 'publish';
		aclEditTopic = '';
	}

	function addAclRule() {
		if (!aclTopic.trim()) return;
		userAcls = [...userAcls, { action: aclAction, topic: aclTopic.trim() }];
		resetAclForm();
	}

	function startEditAclRule(i: number) {
		aclEditIndex = i;
		aclEditAction = userAcls[i].action;
		aclEditTopic = userAcls[i].topic;
	}

	function saveEditAclRule() {
		if (aclEditIndex === null || !aclEditTopic.trim()) return;
		userAcls[aclEditIndex] = { action: aclEditAction, topic: aclEditTopic.trim() };
		userAcls = [...userAcls];
		resetAclForm();
	}

	function deleteAclRule(i: number) {
		userAcls.splice(i, 1);
		userAcls = [...userAcls];
		resetAclForm();
	}
</script>

<style>
:global(html) {
	font-family: 'Inter', 'Roboto', 'Segoe UI', 'Helvetica Neue', Arial, 'Liberation Sans', 'sans-serif';
	background: #181c24;
	font-size: 18px;
	color: #e5e7eb;
}
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
	padding: 2.5rem 2.5rem;
	border-radius: 1.5rem;
	box-shadow: 0 8px 40px rgba(0,0,0,0.10);
	width: 100%;
	max-width: 370px;
	display: flex;
	flex-direction: column;
	gap: 1.5rem;
}
.login-title {
	font-size: 2.2rem;
	font-weight: 800;
	color: #1e293b;
	text-align: center;
	margin-bottom: 0.5rem;
	letter-spacing: -1px;
}
.input-group {
	display: flex;
	flex-direction: column;
	gap: 0.5rem;
}
input[type="text"], input[type="password"] {
	padding: 0.85rem 1.1rem;
	border: 1.5px solid #cbd5e1;
	border-radius: 0.7rem;
	font-size: 1.1rem;
	outline: none;
	transition: border 0.2s;
	background: #f8fafc;
}
input:focus {
	border-color: #2563eb;
	background: #fff;
}
.login-btn {
	background: linear-gradient(90deg, #2563eb 60%, #60a5fa 100%);
	color: white;
	padding: 0.9rem 1.1rem;
	border: none;
	border-radius: 0.7rem;
	font-size: 1.1rem;
	font-weight: 700;
	cursor: pointer;
	transition: background 0.2s, box-shadow 0.2s;
	box-shadow: 0 2px 8px rgba(37,99,235,0.08);
	margin-top: 0.5rem;
}
.login-btn:disabled {
	background: #93c5fd;
	cursor: not-allowed;
}
.error {
	color: #dc2626;
	text-align: center;
	font-size: 1.1rem;
	margin-top: -0.5rem;
}
.admin-root {
	display: flex;
	min-height: 100vh;
	background: linear-gradient(135deg, #23283a 0%, #181c24 100%);
}
.sidebar {
	width: 240px;
	background: #23283a;
	color: #e5e7eb;
	display: flex;
	flex-direction: column;
	align-items: stretch;
	padding: 2rem 1.2rem 1.2rem 1.2rem;
	box-shadow: 2px 0 16px rgba(0,0,0,0.12);
	z-index: 10;
}
.sidebar-title {
	font-size: 1.5rem;
	font-weight: 800;
	margin-bottom: 2.5rem;
	letter-spacing: -1px;
	text-align: center;
	color: #60a5fa;
}
.sidebar-nav {
	list-style: none;
	padding: 0;
	margin: 0;
	display: flex;
	flex-direction: column;
	gap: 1.2rem;
}
.sidebar-nav li {
	padding: 0.7rem 1rem;
	border-radius: 0.6rem;
	font-size: 1.1rem;
	font-weight: 600;
	cursor: pointer;
	transition: background 0.18s, color 0.18s;
	color: #e5e7eb;
}
.sidebar-nav li.active, .sidebar-nav li:hover {
	background: #1e293b;
	color: #60a5fa;
}
.sidebar-nav .logout-link {
	margin-top: auto;
	background: #dc2626;
	color: #fff;
	text-align: center;
	font-weight: 700;
	transition: background 0.18s;
}
.sidebar-nav .logout-link:hover {
	background: #b91c1c;
}
.main-content {
	flex: 1;
	padding: 3.5rem 3.5rem 2.5rem 3.5rem;
	display: flex;
	flex-direction: column;
	gap: 2.5rem;
	background: transparent;
	min-height: 100vh;
}
.dashboard-title {
	font-size: 2.3rem;
	font-weight: 800;
	color: #e5e7eb;
	margin-bottom: 0.5rem;
	letter-spacing: -1px;
}
.dashboard-desc {
	font-size: 1.2rem;
	color: #a3a3a3;
	margin-bottom: 2rem;
}
.user-section {
	background: #23283a;
	border-radius: 1.2rem;
	box-shadow: 0 2px 8px rgba(0,0,0,0.10);
	padding: 2rem 2rem 1.5rem 2rem;
	margin-bottom: 2rem;
}
.user-list-title {
	font-size: 1.15rem;
	font-weight: 700;
	margin-bottom: 0.7rem;
	color: #60a5fa;
}
.user-list {
	display: flex;
	gap: 0.5rem;
	flex-wrap: wrap;
	margin-bottom: 1.5rem;
}
.user-item {
	background: #1e293b;
	padding: 0.5rem 1.1rem;
	border-radius: 0.7rem;
	margin-bottom: 0.5rem;
	display: flex;
	align-items: center;
	gap: 0.5rem;
	cursor: pointer;
	transition: background 0.2s;
	font-size: 1.1rem;
	color: #e5e7eb;
	border: 1.5px solid transparent;
}
.user-item.selected, .user-item:hover {
	background: #2563eb;
	color: #fff;
	border-color: #60a5fa;
}
.delete-btn {
	background: #dc2626;
	color: white;
	border: none;
	border-radius: 0.4rem;
	padding: 0.3rem 0.8rem;
	cursor: pointer;
	font-size: 1rem;
	font-weight: 600;
	margin-left: 0.2rem;
	transition: background 0.18s;
}
.delete-btn:hover {
	background: #b91c1c;
}
.add-user-form {
	display: flex;
	gap: 0.5rem;
	flex-wrap: wrap;
	align-items: flex-end;
	margin-bottom: 1.5rem;
}
.add-user-form input {
	padding: 0.5rem 0.75rem;
	border: 1.5px solid #334155;
	border-radius: 0.7rem;
	font-size: 1.1rem;
	background: #181c24;
	color: #e5e7eb;
}
.add-user-form input:focus {
	border-color: #60a5fa;
	background: #23283a;
}
.add-user-form button {
	background: linear-gradient(90deg, #2563eb 60%, #60a5fa 100%);
	color: white;
	padding: 0.7rem 1.2rem;
	border: none;
	border-radius: 0.7rem;
	font-size: 1.1rem;
	font-weight: 700;
	cursor: pointer;
	transition: background 0.2s, box-shadow 0.2s;
	box-shadow: 0 2px 8px rgba(37,99,235,0.08);
}
.user-details {
	background: #23283a;
	border-radius: 1.2rem;
	box-shadow: 0 2px 8px rgba(0,0,0,0.10);
	padding: 2rem 2rem 1.5rem 2rem;
	margin-top: 1.5rem;
}
.user-details-title {
	font-size: 1.15rem;
	font-weight: 700;
	margin-bottom: 1rem;
	color: #60a5fa;
}
.acl-list {
	list-style: none;
	padding: 0;
	margin: 0 0 1.2rem 0;
}
.acl-rule {
	display: flex;
	align-items: center;
	gap: 0.7rem;
	margin-bottom: 0.5rem;
	font-size: 1.08rem;
}
.acl-action {
	font-weight: 600;
	color: #60a5fa;
}
.acl-on {
	color: #a3a3a3;
	font-weight: 500;
	margin: 0 0.2rem;
}
.acl-topic {
	font-family: monospace;
	background: #181c24;
	padding: 0.1rem 0.4rem;
	border-radius: 0.3rem;
	color: #e5e7eb;
}
.edit-btn, .add-btn, .save-btn, .cancel-btn {
	background: #2563eb;
	color: white;
	padding: 0.3rem 0.8rem;
	border: none;
	border-radius: 0.4rem;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
	margin-left: 0.2rem;
	transition: background 0.2s;
}
.edit-btn { background: #64748b; }
.add-btn { background: #059669; }
.save-btn { background: #059669; }
.save-btn.wide { width: 100%; margin-top: 1rem; }
.cancel-btn { background: #f59e42; }
.delete-btn { background: #dc2626; }
.edit-btn:hover, .add-btn:hover, .save-btn:hover, .cancel-btn:hover, .delete-btn:hover {
	filter: brightness(1.1);
}
input[type="text"], select {
	padding: 0.5rem 0.75rem;
	border: 1.5px solid #334155;
	border-radius: 0.7rem;
	font-size: 1.1rem;
	margin-right: 0.2rem;
	background: #181c24;
	color: #e5e7eb;
}
input[type="text"]:focus, select:focus {
	border-color: #60a5fa;
	outline: none;
	background: #23283a;
}
.acl-add-form {
	display: flex;
	align-items: center;
	gap: 0.5rem;
	margin-top: 1rem;
}
.dashboard-error {
	color: #f87171;
	text-align: center;
	font-size: 1.1rem;
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
	<div class="admin-root">
		<nav class="sidebar">
			<div class="sidebar-title">EMQX Admin</div>
			<ul class="sidebar-nav">
				<li class:active={nav === 'dashboard'} on:click={() => setNav('dashboard')}>Dashboard</li>
				<li class:active={nav === 'users'} on:click={() => setNav('users')}>Users</li>
				<li class:active={nav === 'acls'} on:click={() => setNav('acls')}>ACLs</li>
				<li class="logout-link" on:click={logout}>Logout</li>
			</ul>
		</nav>
		<main class="main-content">
			{#if nav === 'dashboard'}
				<div class="dashboard-title">Welcome to the Admin Dashboard</div>
				<p class="dashboard-desc">Use the sidebar to manage users and ACLs for your EMQX instance.</p>
			{/if}
			{#if nav === 'users'}
				<div class="dashboard-title">User Management</div>
				{#if dashboardError}
					<div class="dashboard-error">{dashboardError}</div>
				{/if}
				<div class="user-section">
					<div class="user-list-title">Users:</div>
					<div class="user-list">
						{#each users as user}
							<div class="user-item {selectedUser === user ? 'selected' : ''}" on:click={() => selectUser(user)}>
								{user}
								<button class="delete-btn" on:click|stopPropagation={() => deleteUser(user)} title="Delete user">✕</button>
							</div>
						{/each}
					</div>
					<form class="add-user-form" on:submit|preventDefault={addUser}>
						<input type="text" placeholder="New username" bind:value={newUser.username} required />
						<input type="password" placeholder="Password" bind:value={newUser.password} required />
						<button type="submit" disabled={dashboardLoading}>Add User</button>
					</form>
				</div>
				{#if selectedUser && nav === 'users'}
					<div class="user-details">
						<div class="user-details-title">ACLs for <span>{selectedUser}</span></div>
						<ul class="acl-list">
							{#each userAcls as rule, i}
								<li class="acl-rule">
									{#if aclEditIndex === i}
										<select bind:value={aclEditAction}>
											<option value="publish">publish</option>
											<option value="subscribe">subscribe</option>
										</select>
										<input type="text" bind:value={aclEditTopic} placeholder="Topic" />
										<button class="save-btn" on:click={saveEditAclRule}>Save</button>
										<button class="cancel-btn" on:click={resetAclForm}>Cancel</button>
										<button class="delete-btn" on:click={() => deleteAclRule(i)}>Delete</button>
									{:else}
										<span class="acl-action">{rule.action}</span> <span class="acl-on">on</span> <span class="acl-topic">{rule.topic}</span>
										<button class="edit-btn" on:click={() => startEditAclRule(i)}>Edit</button>
										<button class="delete-btn" on:click={() => deleteAclRule(i)}>Delete</button>
									{/if}
								</li>
							{/each}
						</ul>
						<div class="acl-add-form">
							<select bind:value={aclAction}>
								<option value="publish">publish</option>
								<option value="subscribe">subscribe</option>
							</select>
							<input type="text" bind:value={aclTopic} placeholder="Topic" />
							<button class="add-btn" on:click={addAclRule}>Add Rule</button>
						</div>
						<button class="save-btn wide" on:click={updateAcls} disabled={dashboardLoading}>Save ACLs</button>
					</div>
				{/if}
			{/if}
			{#if nav === 'acls'}
				<div class="dashboard-title">ACL Management</div>
				<p class="dashboard-desc">Select a user in the Users tab to manage their ACLs.</p>
			{/if}
		</main>
	</div>
{/if}
