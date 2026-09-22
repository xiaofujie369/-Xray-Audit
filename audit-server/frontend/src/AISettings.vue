<script setup lang="ts">
import { onMounted, ref } from 'vue'
const props=defineProps<{api:(path:string,method?:string,body?:unknown)=>Promise<any>,admin:boolean}>()
const state=ref<any>(null), error=ref(''), busy=ref(false), saved=ref(false)
async function load(){try{state.value=await props.api('ai/settings')}catch(e){error.value=String(e)}}
async function save(){busy.value=true;error.value='';saved.value=false;try{state.value=await props.api('ai/settings','PATCH',state.value.options);saved.value=true}catch(e){error.value=String(e)}finally{busy.value=false}}
onMounted(load)
</script>
<template>
 <section>
  <h2>AI 只读调查</h2>
  <p>每分钟检查事件证据变化。有新证据时生成辅助报告，不会封禁用户、修改路由或操作 Xray。</p>
  <p class="notice">启用后会向你配置的模型服务发送脱敏对象标识、汇总统计和探测结果。不会发送真实用户 ID、来源 IP、目标 IP、域名、操作备注或原始日志。模型结论需人工核查。</p>
  <p v-if="error" class="error" role="alert">{{error}}</p>
  <template v-if="state">
   <p>模型配置：{{state.configured?'已配置':'未配置'}} · 模型：{{state.model||'未设置'}}</p>
   <p>今日请求 {{state.requests_today}} / {{state.options.daily_request_limit}}（UTC {{state.usage_day_utc}}，包括失败请求）</p>
   <p v-if="!state.configured">在中央服务器 .env 中配置 AI_API_URL（完整 HTTPS Chat Completions 地址）、AI_API_KEY 和 AI_MODEL，然后重新创建中央服务容器。密钥不会显示在管理后台。</p>
   <form @submit.prevent="save">
    <fieldset :disabled="!admin||busy">
     <label><input v-model="state.options.enabled" type="checkbox">启用脱敏证据的外部 AI 分析</label>
     <div class="toolbar">
      <label>每日最多请求次数<input v-model.number="state.options.daily_request_limit" type="number" min="1" max="10000" required></label>
      <label>同一事件分析间隔（秒）<input v-model.number="state.options.event_cooldown_seconds" type="number" min="60" max="86400" required></label>
      <label>每次输出 token 上限<input v-model.number="state.options.max_output_tokens" type="number" min="512" max="8192" required></label>
     </div>
     <button v-if="admin">{{busy?'保存中…':'保存 AI 设置'}}</button>
    </fieldset>
   </form>
   <p v-if="saved" role="status">设置已保存。报告将在事件详情中显示。</p>
  </template>
 </section>
</template>
