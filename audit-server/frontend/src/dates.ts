import { ref } from 'vue'
export const timezone = ref('browser')
export function formatDate(value:string) {
  return new Date(value).toLocaleString('zh-CN', timezone.value==='browser'?{}:{timeZone:timezone.value})
}
