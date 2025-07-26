<script lang="ts">
import { onMount } from 'svelte';

let mounted = false;

onMount(() => {
	mounted = true;
});
</script>

<div class="dashboard-title">Welcome to the Admin Dashboard</div>
<p class="dashboard-desc">Use the sidebar to manage users and ACLs for CARRELink.</p>

<style>
.dashboard-title {
	font-size: 2rem;
	font-weight: 700;
	color: #e5e7eb;
	margin-bottom: 0.5rem;
	letter-spacing: -0.5px;
}
.dashboard-desc {
	font-size: 1.1rem;
	color: #9ca3af;
	margin-bottom: 2rem;
}
</style>
