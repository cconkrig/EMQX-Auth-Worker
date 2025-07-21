<script>
  import { onMount } from 'svelte';
  let username = '';
  let password = '';
  let jwt = '';
  let loginError = '';
  let loggedIn = false;
  let users = [];
  let selectedUser = '';
  let acls = [];
  let aclAction = '';
  let aclTopic = '';
  let userMessage = '';
  let aclMessage = '';
  let userError = '';
  let aclError = '';
  let confirmDelete = '';

  function login() {
    fetch('/admin/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    })
      .then(r => r.json())
      .then(data => {
        if (data.token) {
          jwt = data.token;
          localStorage.setItem('jwt', jwt);
          loggedIn = true;
          loginError = '';
          fetchUsers();
        } else {
          loginError = data.error || 'Login failed';
        }
      });
  }

  function logout() {
    jwt = '';
    localStorage.removeItem('jwt');
    loggedIn = false;
    users = [];
    selectedUser = '';
    acls = [];
    userMessage = '';
    aclMessage = '';
    userError = '';
    aclError = '';
  }

  function fetchUsers() {
    fetch('/admin/api/users', {
      headers: { 'Authorization': 'Bearer ' + jwt }
    })
      .then(r => r.json())
      .then(data => {
        users = data.users || [];
      });
  }

  function selectUser(user) {
    selectedUser = user;
    aclMessage = '';
    aclError = '';
    fetch(`/admin/api/user-details?username=${user}`, {
      headers: { 'Authorization': 'Bearer ' + jwt }
    })
      .then(r => r.json())
      .then(u => {
        if (u.acls) {
          acls = u.acls;
        } else {
          acls = [];
        }
      });
  }

  function createOrUpdateUser() {
    userMessage = '';
    userError = '';
    fetch('/admin/api/user', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + jwt },
      body: JSON.stringify({ username, password, acls })
    })
      .then(r => r.json())
      .then(data => {
        if (data.success) {
          userMessage = 'User created/updated!';
          userError = '';
          fetchUsers();
          username = '';
          password = '';
        } else {
          userError = data.error || 'Error creating/updating user';
        }
      });
  }

  function deleteUser(user) {
    userMessage = '';
    userError = '';
    if (confirmDelete !== user) {
      confirmDelete = user;
      userError = `Click delete again to confirm deleting ${user}`;
      return;
    }
    fetch('/admin/api/user', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + jwt },
      body: JSON.stringify({ username: user })
    })
      .then(r => r.json())
      .then(data => {
        if (data.success) {
          userMessage = 'User deleted!';
          userError = '';
          fetchUsers();
          if (selectedUser === user) {
            selectedUser = '';
            acls = [];
          }
        } else {
          userError = data.error || 'Error deleting user';
        }
        confirmDelete = '';
      });
  }

  function addAcl() {
    if (!aclAction || !aclTopic) return;
    acls = [...acls, { action: aclAction, topic: aclTopic }];
    aclAction = '';
    aclTopic = '';
  }

  function updateAcls() {
    aclMessage = '';
    aclError = '';
    fetch('/admin/api/acl', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + jwt },
      body: JSON.stringify({ username: selectedUser, acls })
    })
      .then(r => r.json())
      .then(data => {
        if (data.success) {
          aclMessage = 'ACLs updated!';
          aclError = '';
        } else {
          aclError = data.error || 'Error updating ACLs';
        }
      });
  }

  function removeAcl(i) {
    acls = acls.slice(0, i).concat(acls.slice(i + 1));
  }

  onMount(() => {
    jwt = localStorage.getItem('jwt') || '';
    loggedIn = !!jwt;
    if (loggedIn) fetchUsers();
  });
</script>

{#if !loggedIn}
  <h2>Admin Login</h2>
  <input placeholder="Username" bind:value={username} />
  <input placeholder="Password" type="password" bind:value={password} />
  <button on:click={login}>Login</button>
  {#if loginError}<div style="color:red">{loginError}</div>{/if}
{:else}
  <h2>Admin Panel</h2>
  <button on:click={logout}>Logout</button>
  <div>
    <h3>Users</h3>
    <ul>
      {#each users as user}
        <li style="{selectedUser === user ? 'font-weight:bold' : ''}">
          <button type="button" on:click={() => selectUser(user)} aria-label="Select user {user}" style="cursor:pointer; background:none; border:none; padding:0; font:inherit; text-align:left;{selectedUser === user ? 'font-weight:bold' : ''}">{user}</button>
          <button on:click={() => deleteUser(user)}>{confirmDelete === user ? 'Confirm Delete' : 'Delete'}</button>
        </li>
      {/each}
    </ul>
    <h4>Create/Update User</h4>
    <input placeholder="Username" bind:value={username} />
    <input placeholder="Password" type="password" bind:value={password} />
    <button on:click={createOrUpdateUser}>Create/Update</button>
    {#if userMessage}<div style="color:green">{userMessage}</div>{/if}
    {#if userError}<div style="color:red">{userError}</div>{/if}
    {#if selectedUser}
      <h4>ACLs for {selectedUser}</h4>
      <ul>
        {#each acls as acl, i}
          <li>{acl.action} - {acl.topic} <button on:click={() => removeAcl(i)}>Remove</button></li>
        {/each}
      </ul>
      <input placeholder="Action (publish/subscribe)" bind:value={aclAction} />
      <input placeholder="Topic" bind:value={aclTopic} />
      <button on:click={addAcl}>Add ACL</button>
      <button on:click={updateAcls}>Update ACLs</button>
      {#if aclMessage}<div style="color:green">{aclMessage}</div>{/if}
      {#if aclError}<div style="color:red">{aclError}</div>{/if}
    {/if}
  </div>
{/if} 