<script lang="ts">
import { onMount } from 'svelte';
let token: string | null = null;
let users: string[] = [];
let selectedUser: string | null = null;
let userAcls: any[] = [];
let newUser = { username: '', password: '' };
let dashboardError = '';
let dashboardLoading = false;

// ACL UI state
let aclAction = 'publish';
let aclTopic = '';
let aclEditIndex: number | null = null;
let aclEditAction = 'publish';
let aclEditTopic = '';

function getToken() {
	return localStorage.getItem('admin_token');
}

onMount(() => {
	token = getToken();
	if (token) loadUsers();
});

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
				acls: []
			})
		});
		if (!res.ok) throw new Error('Failed to add user');
		await loadUsers();
		newUser = { username: '', password: '' };
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
		const res = await fetch('/admin/api/acl', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${token}`
			},
			body: JSON.stringify({ username: selectedUser, acls: userAcls })
		});
		if (!res.ok) throw new Error('Failed to update ACLs');
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
{#if selectedUser}
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
</style> 