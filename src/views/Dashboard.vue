<template>
  <div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h1>Incus Web 管理器</h1>
      <button @click="logout" class="btn btn-outline-danger btn-sm">退出登录</button>
    </div>

    <div v-if="globalError" class="alert alert-danger">
      <strong>错误:</strong> {{ globalError }}
    </div>

    <div class="row gx-4">
      <div class="col-lg-7 col-md-6 mb-4 mb-md-0">
        <ContainerList @open-modal="handleOpenModal" />
      </div>
      <div class="col-lg-5 col-md-6">
        <CreateContainer />
      </div>
    </div>

    <InfoModal :container-name="selectedContainer" ref="infoModal" />
    <ExecModal :container-name="selectedContainer" ref="execModal" />
    <NatModal :container-name="selectedContainer" ref="natModal" />
    <ReverseProxyModal :container-name="selectedContainer" ref="reverseProxyModal" />
    <SshModal :container-name="selectedContainer" ref="sshModal" />
    <QuickCommandsModal ref="quickCommandsModal" />
    
  </div>
</template>

<script setup>
import { ref, onMounted, provide } from 'vue'
import { useRouter } from 'vue-router'
import ContainerList from '@/components/ContainerList.vue'
import CreateContainer from '@/components/CreateContainer.vue'
import InfoModal from '@/components/InfoModal.vue'
import ExecModal from '@/components/ExecModal.vue'
import NatModal from '@/components/NatModal.vue'
import ReverseProxyModal from '@/components/ReverseProxyModal.vue'
import SshModal from '@/components/SshModal.vue'
import QuickCommandsModal from '@/components/QuickCommandsModal.vue'
import { api } from '@/services/api'


const router = useRouter()
const globalError = ref(null)
const containers = ref([])
const images = ref([])
const pools = ref([])

const selectedContainer = ref(null)
const infoModal = ref(null)
const execModal = ref(null)
const natModal = ref(null)
const reverseProxyModal = ref(null)
const sshModal = ref(null)

const fetchData = async () => {
    try {
        const [containersRes, imagesRes, poolsRes] = await Promise.all([
            api.getContainers(),
            api.getImages(),
            api.getStoragePools()
        ]);
        containers.value = containersRes.data;
        images.value = imagesRes.data;
        pools.value = poolsRes.data;
    } catch (error) {
        globalError.value = '加载初始数据失败。请检查后端服务是否正常。';
        console.error(error);
    }
};


onMounted(fetchData)

// Provide/Inject 来传递数据给子组件
provide('containers', containers)
provide('images', images)
provide('pools', pools)
provide('fetchData', fetchData)

const handleOpenModal = ({ modal, containerName }) => {
  selectedContainer.value = containerName;
  // nextTick a;
  switch (modal) {
    case 'info': infoModal.value.show(); break;
    case 'exec': execModal.value.show(); break;
    case 'nat': natModal.value.show(); break;
    case 'revproxy': reverseProxyModal.value.show(); break;
    case 'ssh': sshModal.value.show(); break;
  }
};

const logout = () => {
  localStorage.removeItem('user_logged_in')
  router.push('/login')
}
</script>
