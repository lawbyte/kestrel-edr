<script setup lang="ts">
import { computed } from 'vue'
import { useData, withBase } from 'vitepress'

const props = defineProps<{
  /** Theme-matched pair: "console/overview" -> img/console/overview-dark.png and -light.png. */
  name?: string
  /** A single image path under public/, for example "img/tray/status.png". */
  src?: string
  alt: string
  caption?: string
}>()

const { isDark } = useData()

const url = computed(() => {
  if (props.src) return withBase('/' + props.src.replace(/^\//, ''))
  const variant = isDark.value ? 'dark' : 'light'
  return withBase(`/img/${props.name}-${variant}.png`)
})
</script>

<template>
  <figure class="kestrel-shot">
    <a :href="url" target="_blank" rel="noopener">
      <img :src="url" :alt="alt" loading="lazy" />
    </a>
    <figcaption v-if="caption">{{ caption }}</figcaption>
  </figure>
</template>
