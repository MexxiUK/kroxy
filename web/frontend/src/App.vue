<script setup lang="ts">
import { ref, onMounted } from 'vue'

interface Route {
  id: number
  domain: string
  backend: string
  enabled: boolean
  waf_enabled: boolean
  oidc_enabled: boolean
}

const routes = ref<Route[]>([])
const loading = ref(true)
const error = ref<string | null>(null)

const newRoute = ref({
  domain: '',
  backend: '',
  enabled: true,
  waf_enabled: true,
  oidc_enabled: false
})

async function fetchRoutes() {
  try {
    loading.value = true
    const res = await fetch('/api/routes')
    if (!res.ok) throw new Error('Failed to fetch routes')
    routes.value = await res.json()
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    loading.value = false
  }
}

async function createRoute() {
  try {
    const res = await fetch('/api/routes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newRoute.value)
    })
    if (!res.ok) throw new Error('Failed to create route')
    const route = await res.json()
    routes.value.push(route)
    newRoute.value = { domain: '', backend: '', enabled: true, waf_enabled: true, oidc_enabled: false }
  } catch (e) {
    error.value = (e as Error).message
  }
}

async function deleteRoute(id: number) {
  try {
    const res = await fetch(`/api/routes/${id}`, { method: 'DELETE' })
    if (!res.ok) throw new Error('Failed to delete route')
    routes.value = routes.value.filter(r => r.id !== id)
  } catch (e) {
    error.value = (e as Error).message
  }
}

onMounted(fetchRoutes)
</script>

<template>
  <div class="min-h-screen bg-gray-100">
    <nav class="bg-white shadow-sm">
      <div class="max-w-7xl mx-auto px-4 py-4">
        <h1 class="text-2xl font-bold text-gray-900">Kroxy</h1>
        <p class="text-sm text-gray-500">Self-hosted reverse proxy with WAF and OIDC — no paywalls</p>
      </div>
    </nav>

    <main class="max-w-7xl mx-auto px-4 py-8">
      <div v-if="error" class="bg-red-100 text-red-700 p-4 rounded mb-4">
        {{ error }}
      </div>

      <!-- Add Route Form -->
      <div class="bg-white rounded-lg shadow p-6 mb-8">
        <h2 class="text-lg font-semibold mb-4">Add New Route</h2>
        <form @submit.prevent="createRoute" class="space-y-4">
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <input
              v-model="newRoute.domain"
              type="text"
              placeholder="Domain (e.g., app.example.com)"
              class="border rounded px-3 py-2 w-full"
              required
            />
            <input
              v-model="newRoute.backend"
              type="text"
              placeholder="Backend (e.g., http://localhost:3000)"
              class="border rounded px-3 py-2 w-full"
              required
            />
          </div>
          <div class="flex items-center space-x-4">
            <label class="flex items-center">
              <input type="checkbox" v-model="newRoute.enabled" class="mr-2" />
              Enabled
            </label>
            <label class="flex items-center">
              <input type="checkbox" v-model="newRoute.waf_enabled" class="mr-2" />
              WAF
            </label>
            <label class="flex items-center">
              <input type="checkbox" v-model="newRoute.oidc_enabled" class="mr-2" />
              OIDC
            </label>
          </div>
          <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">
            Add Route
          </button>
        </form>
      </div>

      <!-- Routes List -->
      <div class="bg-white rounded-lg shadow">
        <div v-if="loading" class="p-4 text-center text-gray-500">Loading...</div>
        <div v-else-if="routes.length === 0" class="p-4 text-center text-gray-500">
          No routes configured yet. Add one above to get started.
        </div>
        <table v-else class="w-full">
          <thead class="bg-gray-50">
            <tr>
              <th class="px-4 py-3 text-left">Domain</th>
              <th class="px-4 py-3 text-left">Backend</th>
              <th class="px-4 py-3 text-left">Status</th>
              <th class="px-4 py-3 text-left">Features</th>
              <th class="px-4 py-3 text-left">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y">
            <tr v-for="route in routes" :key="route.id">
              <td class="px-4 py-3">{{ route.domain }}</td>
              <td class="px-4 py-3 font-mono text-sm">{{ route.backend }}</td>
              <td class="px-4 py-3">
                <span :class="route.enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'" class="px-2 py-1 rounded text-sm">
                  {{ route.enabled ? 'Active' : 'Disabled' }}
                </span>
              </td>
              <td class="px-4 py-3">
                <span v-if="route.waf_enabled" class="bg-blue-100 text-blue-800 px-2 py-1 rounded text-sm mr-1">WAF</span>
                <span v-if="route.oidc_enabled" class="bg-purple-100 text-purple-800 px-2 py-1 rounded text-sm">OIDC</span>
              </td>
              <td class="px-4 py-3">
                <button @click="deleteRoute(route.id)" class="text-red-600 hover:text-red-800">
                  Delete
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </main>
  </div>
</template>