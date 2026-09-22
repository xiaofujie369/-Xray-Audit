<script setup lang="ts">
import {computed,onMounted,onUnmounted,ref,watch} from 'vue'
import InfoPanel from './InfoPanel.vue'
import {formatDate} from './dates'
const props=defineProps<{eventId:string,api:(path:string,method?:string,body?:unknown)=>Promise<any>,admin:boolean}>()
const snapshot=ref<any>(null), reports=ref<any[]>([]), windowMinutes=ref('60'), error=ref(''), busy=ref(false)
const selectedReport=ref<any>(null), entityDetails=ref<any>(null)
const labels:Record<string,string>={user:'用户',source_ip:'来源 IP',domain:'域名',destination_ip:'目标 IP',node:'节点'}
const routes:Record<string,string>={user:'users',source_ip:'source-ips',domain:'domains',destination_ip:'destination-ips',node:'nodes'}
const states:Record<string,string>={pending:'等待分析',running:'分析中',succeeded:'已生成',failed:'失败',superseded:'已被新证据替代'}
const windowData=computed(()=>snapshot.value?.evidence?.windows?.[windowMinutes.value])
const review=computed(()=>selectedReport.value?.result?.report)
let timer:ReturnType<typeof setInterval>|undefined
async function load(){
 if(busy.value)return
 busy.value=true;error.value=''
 try{
  const [evidence,result]=await Promise.all([props.api('block-events/'+props.eventId+'/investigation'),props.api('block-events/'+props.eventId+'/ai-reports')])
  reports.value=result.items
  if(!selectedReport.value)snapshot.value=evidence
  else {const current=result.items.find((r:any)=>r.id===selectedReport.value.id);if(current)selectedReport.value=current}
 }catch(e){error.value=String(e)}finally{busy.value=false}
}
async function selectReport(report:any){error.value='';try{snapshot.value=await props.api('block-events/'+props.eventId+'/investigation?snapshot_id='+report.snapshot_id);selectedReport.value=report}catch(e){error.value=String(e)}}
async function latest(){selectedReport.value=null;await load()}
async function retry(report:any){try{await props.api('ai/reports/'+report.id+'/retry','POST');await load()}catch(e){error.value=String(e)}}
async function inspect(kind:string,key:string){
 error.value=''
 try{
  const result=await props.api('correlation/'+routes[kind]+'?key='+encodeURIComponent(key)+'&size=100')
  entityDetails.value={entity_type:kind,entity_key:key,correlations:result.items,has_more:result.has_more}
 }catch(e){error.value=String(e)}
}
function focusEvidence(refId:string){
 if(/^W(15|30|60)$/.test(refId))windowMinutes.value=refId.slice(1)
 requestAnimationFrame(()=>{const element=document.getElementById('evidence-'+refId);if(element instanceof HTMLDetailsElement)element.open=true;element?.scrollIntoView({behavior:'smooth',block:'center'})})
}
watch(()=>props.eventId,()=>{selectedReport.value=null;entityDetails.value=null;load()})
onMounted(()=>{load();timer=setInterval(()=>{if(!document.hidden)load()},60000)})
onUnmounted(()=>{if(timer)clearInterval(timer)})
</script>
<template>
 <section class="investigation">
  <h2>事件证据与关联调查</h2>
  <div class="toolbar"><button :disabled="busy" @click="latest">查看最新证据</button><span v-if="selectedReport">正在查看所选 AI 报告引用的证据版本</span></div>
  <p v-if="error" class="error" role="alert">{{error}}</p>
  <p v-if="snapshot?.status==='pending'">调查正在排队。每分钟检查新事件及补传数据；可使用上方“重新计算”。</p>
  <template v-if="snapshot?.status==='ready'">
   <p class="muted">证据版本 {{snapshot.id}} · 保存于 {{formatDate(snapshot.created_at)}}</p>
   <p class="muted">历史事件保留当时状态。旧版判定不等同于满足 V2 标准；请展开探测证据查看对照条件与缺失项。</p>
   <div id="evidence-E0" class="notice">
    事件时间区间：{{snapshot.evidence.last_known_good_at?formatDate(snapshot.evidence.last_known_good_at):'最后正常时间未知'}} → {{formatDate(snapshot.evidence.first_known_bad_at)}}（首次异常）。探测不能确定精确屏蔽时刻。
   </div>
   <div class="toolbar"><button v-for="m in ['15','30','60']" :key="m" :class="{active:windowMinutes===m}" @click="windowMinutes=m">事件前 {{m}} 分钟</button></div>
   <section v-if="windowData" :id="'evidence-W'+windowMinutes">
    <p>{{formatDate(windowData.start)}} — {{formatDate(windowData.end)}} · {{windowData.connections}} 次连接 · {{windowData.aggregate_rows}} 条聚合记录</p>
    <p class="muted">仅反映收到并保存的记录，缺少记录不代表没有活动。每类对象最多显示 50 项；计数不是因果证据。</p>
    <details><summary>连接关联明细（按连接次数取前 100 组）</summary><p class="muted">保留用户、来源、节点、目标与端口的组合，不代表完整访问历史。</p><InfoPanel :value="windowData.connection_groups||[]"/></details>
    <details v-for="(items,kind) in windowData.entities" :key="kind"><summary>{{labels[String(kind)]||kind}}（窗口内连接次数）</summary>
     <div class="table-wrap"><table><thead><tr><th>对象</th><th>连接次数</th><th>跨事件 / 跨 VPS</th></tr></thead><tbody><tr v-for="row in (items as any[])" :key="row.key"><td>{{row.key}}</td><td>{{row.connections}}</td><td><button @click="inspect(String(kind),row.key)">关联记录</button></td></tr></tbody></table></div>
    </details>
   </section>
   <h3>正常基线校正后的关联度</h3>
   <p class="muted">评分窗口为事件配置的调查窗口；上方 15 / 30 / 60 分钟切换只改变连接统计，不改变此评分。基线不足时不能判定异常关联。</p>
   <div class="table-wrap"><table><thead><tr><th>证据</th><th>对象</th><th>关联度</th><th>正常基线提升</th><th>事件 / VPS 数</th><th>解释</th></tr></thead><tbody>
    <tr v-for="(row,index) in snapshot.evidence.correlations" :key="row.entity_type+row.key" :id="'evidence-C'+(Number(index)+1)"><td>C{{Number(index)+1}}</td><td><button class="link" @click="inspect(row.entity_type,row.key)">{{labels[row.entity_type]}} · {{row.key}}</button></td><td>{{row.score}}</td><td>{{row.details.insufficient_baseline?'基线不足':Number(row.details.baseline_lift).toFixed(2)+' 倍'}}</td><td>{{row.details.appearances}} / {{row.details.cross_vps}}</td><td><details><summary>评分依据</summary><InfoPanel :value="row.details"/></details></td></tr>
   </tbody></table></div>
   <details v-for="(item,index) in snapshot.evidence.probe_evidence.slice(-10)" :key="index" :id="'evidence-P'+(Number(index)+1)"><summary>P{{Number(index)+1}} · 探测共识证据 {{formatDate(item.time)}}</summary><InfoPanel :value="item"/></details>
  </template>
  <section v-if="entityDetails"><h3>跨事件关联记录（最多 100 条）</h3><p>{{labels[entityDetails.entity_type]}} · {{entityDetails.entity_key}}</p><p v-if="entityDetails.has_more">还有更多记录，可在“关联度”页面按对象搜索并翻页。</p><div class="table-wrap"><table><thead><tr><th>事件 ID</th><th>VPS</th><th>首次异常</th><th>关联度</th><th>解释</th></tr></thead><tbody><tr v-for="row in entityDetails.correlations" :key="row.id"><td>{{row.block_event_id}}</td><td>{{row.vps_id}}</td><td>{{formatDate(row.incident_time)}}</td><td>{{row.score}}</td><td><details><summary>基线与关联依据</summary><InfoPanel :value="row.details"/></details></td></tr></tbody></table></div><button @click="entityDetails=null">关闭对象详情</button></section>
  <h3>AI 辅助报告</h3>
  <p v-if="!reports.length">暂无报告。管理员可在“AI 调查”中配置并启用；关闭 AI 不影响证据保存与关联计算。</p>
  <div class="toolbar" v-for="report in reports" :key="report.id"><button @click="selectReport(report)">{{formatDate(report.created_at)}} · {{states[report.status]||report.status}}</button><span v-if="report.error_code">{{report.error_code}}</span><button v-if="admin&&report.status==='failed'" @click="retry(report)">重试</button></div>
  <article v-if="review" class="notice"><p>{{selectedReport.result.disclaimer}}</p><h3>{{review.summary}}</h3><ul><li v-for="(finding,index) in review.findings" :key="index">{{finding.text}} <button v-for="refId in finding.evidence_refs" :key="refId" class="link" @click="focusEvidence(refId)">[{{refId}}]</button></li></ul><h4>证据局限</h4><ul><li v-for="item in review.limitations" :key="item">{{item}}</li></ul><h4>建议人工核查</h4><ul><li v-for="item in review.next_checks" :key="item">{{item}}</li></ul></article>
 </section>
</template>
