<script lang="ts">
import { onMount } from 'svelte';

let message = 'Hello World';
let mounted = false;

onMount(() => {
	mounted = true;
});
</script>

<div class="dashboard-title">Welcome to the Admin Dashboard</div>
<p class="dashboard-desc">Use the sidebar to manage users and ACLs for your EMQX instance.</p>

<style>
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
</style>
