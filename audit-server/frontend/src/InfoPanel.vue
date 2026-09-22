<script setup lang="ts">
import { computed } from 'vue'
import {formatDate} from './dates'
const props = defineProps<{value: unknown}>()
const entries = computed(() => props.value && typeof props.value === 'object' && !Array.isArray(props.value) ? Object.entries(props.value) : [])
const labels: Record<string,string> = {
 mainland:'大陆探测点',controls_current:'对照配置版本一致',outside_mainland_success_groups:'境外成功网络组',healthy_xray_heartbeat:'近期 Xray 健康心跳',missing_confirmation_evidence:'仍缺少的确认依据',interpretation:'说明',
 single_network:'仅一个独立网络（低置信度）',control_targets_configured:'已配置控制目标',connection_trend:'连接趋势',label:'时间 / 对象',value:'数值',normal:'正常',id:'ID',name:'名称',region:'区域',provider:'供应商',hostname:'主机名',vps_id:'VPS',node_id:'节点 ID',user_id:'XBoard 用户',
 source_ip:'来源 IP',destination_domain:'目标域名',destination_ip:'目标 IP',target_ip:'探测 IP',target_port:'探测端口',
 window_start:'调查开始',window_end:'调查结束',first_seen:'首次出现',last_seen:'最后出现',connections:'连接次数',
 first_known_bad_at:'首次异常时间',last_known_good_at:'最后正常时间',detected_at:'检测时间',recovered_at:'恢复时间',
 state:'状态',source:'来源',confidence:'探测置信度',probe_count:'独立探测网络数',evidence:'探测证据',notes:'备注',
 probe:'探测点',group:'独立网络组',results:'结果',success:'成功',control_ok:'控制目标正常',error:'错误类别',latency_ms:'延迟（ms）',time:'时间',
 score:'关联度',details:'评分解释',baseline_method:'基线方法',baseline_connections:'基线连接次数',baseline_total:'基线总连接数',baseline_lift:'基线提升倍数',
 insufficient_baseline:'基线不足',appearances:'事件前出现次数',total_events:'事件总数',cross_vps:'跨 VPS 数',distinct_users:'用户数',distinct_source_ips:'来源 IP 数',distinct_vps:'VPS 数',
 event_share:'事件窗口占比',temporal_proximity:'时间接近度',weights:'评分权重',formula:'计算公式',entity:'对象',entity_key:'对象',entity_type:'对象类型',block_event_id:'事件 ID',
 correlations:'跨事件关联',user_traffic:'用户总流量（非域名流量）',uplink_bytes:'上行字节',downlink_bytes:'下行字节',
 ip_history:'IP 历史',address:'地址',family:'地址类型',current:'当前地址',targets:'探测目标',port:'端口',protocol:'协议',server_name:'服务器名称',path:'健康检查路径',enabled:'启用',
 activity_24h:'最近 24 小时活动（前 20 项）',activity:'调查窗口活动（前 20 项）',recent_incidents:'最近事件',
 health:'Agent 健康',agent_version:'Agent 版本',xray_version:'Xray 版本',last_heartbeat_at:'最后心跳',created_at:'创建时间',
 spool_rows:'待传批次数',spool_bytes:'spool 字节数',spool_capacity:'spool 容量',last_upload:'最后上传时间',oldest_batch:'最早待传批次',evicted_batches:'容量淘汰批次',parser_errors:'解析异常次数',last_access_log_time:'最近日志时间'
}
const text: Record<string,string> = {hourly_same_hour_previous_7_days:'前 7 天同小时汇总基线',hourly_previous_24h_excluding_incidents:'前 24 小时汇总基线（排除事件）',insufficient_independent_mainland_failures:'独立大陆失败网络不足',no_recent_outside_mainland_success:'缺少近期境外成功对照',no_control_targets_configured:'未配置对照目标',no_recent_healthy_xray_heartbeat:'缺少近期 Xray 健康心跳',insufficient_current_control_evidence_or_network_groups:'对照版本证据或独立网络分组不足',suspected:'疑似屏蔽',confirmed:'符合屏蔽特征',recovered:'已恢复',manual:'手动',probe:'探测',false_positive:'疑似后恢复',same_hour_previous_7_days:'前 7 天同时间段',previous_24h_excluding_incidents:'前 24 小时（排除事件窗口）',user:'用户',domain:'域名',source_ip:'来源 IP',destination_ip:'目标 IP'}
function format(value:unknown){ if(value==null)return '—';if(typeof value==='boolean')return value?'是':'否';const s=String(value);if(/^\d{4}-\d{2}-\d{2}T/.test(s))return formatDate(s);return text[s]||s }
</script>
<template>
 <div v-if="Array.isArray(value)" class="nested-list"><InfoPanel v-for="(item,index) in value" :key="index" :value="item"/><span v-if="!value.length">暂无数据</span></div>
 <dl v-else-if="entries.length"><template v-for="[key,item] in entries" :key="key"><dt>{{labels[key]||key}}</dt><dd><InfoPanel v-if="item!==null&&typeof item==='object'" :value="item"/><span v-else>{{format(item)}}</span></dd></template></dl>
 <span v-else>{{format(value)}}</span>
</template>
