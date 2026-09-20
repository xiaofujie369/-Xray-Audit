<script setup lang="ts">
import { computed } from 'vue'
const props = defineProps<{ title:string, items?: {label:string,value:number}[] }>()
const maximum = computed(()=>Math.max(1,...(props.items||[]).map(x=>x.value)))
</script>
<template>
 <article class="chart"><h2>{{title}}</h2><p v-if="!items?.length" class="muted">暂无数据</p>
  <div v-for="(item,index) in items" :key="index" class="chart-row">
   <span :title="item.label">{{item.label}}</span><div class="bar-track"><div class="bar" :style="{width:Math.max(.5,item.value/maximum*100)+'%'}"></div></div><strong>{{Number(item.value).toLocaleString()}}</strong>
  </div>
 </article>
</template>
<style scoped>
.chart{border:1px solid #2c414e;border-radius:8px;background:#162530;padding:20px;min-width:0}.chart h2{margin:0 0 20px}.chart-row{display:grid;grid-template-columns:minmax(80px,1fr) 2fr 65px;gap:12px;align-items:center;margin:12px 0;font-size:12px}.chart-row>span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.chart-row>strong{text-align:right;font-weight:500}.bar-track{background:#223844;border-radius:3px;overflow:hidden;height:10px}.bar{background:#73cdb4;height:100%;border-radius:3px}
</style>
