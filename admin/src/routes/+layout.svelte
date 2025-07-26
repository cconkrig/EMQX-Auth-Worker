<script lang="ts">
import { page } from '$app/stores';
import { onMount } from 'svelte';
import { goto } from '$app/navigation';

let isAuthenticated = false;
let isLoading = true;

onMount(() => {
	const token = localStorage.getItem('admin_token');
	if (!token) {
		goto('/admin/login');
		return;
	}
	
	// Verify token is still valid by making a test request
	fetch('/admin/api/users', {
		headers: { Authorization: `Bearer ${token}` }
	}).then(res => {
		if (res.ok) {
			isAuthenticated = true;
		} else {
			localStorage.removeItem('admin_token');
			goto('/admin/login');
		}
	}).catch(() => {
		localStorage.removeItem('admin_token');
		goto('/admin/login');
	}).finally(() => {
		isLoading = false;
	});
});

function logout() {
	localStorage.removeItem('admin_token');
	goto('/admin/login');
}
</script>

{#if isLoading}
	<div class="loading-container">
		<div class="loading-spinner"></div>
		<p>Loading...</p>
	</div>
{:else if isAuthenticated}
	<main class="admin-root">
		<nav class="sidebar">
			<div class="sidebar-title">EMQX Admin</div>
			<ul class="sidebar-nav">
				<li><a href="/admin/" class:active={$page.url.pathname === '/admin/'}>Dashboard</a></li>
				<li><a href="/admin/users" class:active={$page.url.pathname === '/admin/users'}>Users</a></li>
				<li><a href="/admin/acls" class:active={$page.url.pathname === '/admin/acls'}>ACLs</a></li>
				<li><button type="button" class="logout-link" on:click={logout}>Logout</button></li>
			</ul>
		</nav>
		<section class="main-content">
			<slot />
		</section>
	</main>
{/if}

<style>
:global(html) {
	font-family: 'Inter', 'Roboto', 'Segoe UI', 'Helvetica Neue', Arial, 'Liberation Sans', 'sans-serif';
	background: #181c24;
	font-size: 18px;
	color: #e5e7eb;
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
.sidebar-nav li a {
	color: inherit;
	text-decoration: none;
	display: block;
	width: 100%;
}
.sidebar-nav li a.active, .sidebar-nav li a:hover {
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
	border: none;
	border-radius: 0.6rem;
	padding: 0.7rem 1rem;
	font-size: 1.1rem;
	cursor: pointer;
	width: 100%;
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

.loading-container {
	display: flex;
	flex-direction: column;
	align-items: center;
	justify-content: center;
	min-height: 100vh;
	background: linear-gradient(135deg, #23283a 0%, #181c24 100%);
	color: #e5e7eb;
}

.loading-spinner {
	width: 40px;
	height: 40px;
	border: 4px solid #374151;
	border-top: 4px solid #60a5fa;
	border-radius: 50%;
	animation: spin 1s linear infinite;
	margin-bottom: 1rem;
}

@keyframes spin {
	0% { transform: rotate(0deg); }
	100% { transform: rotate(360deg); }
}
</style> 