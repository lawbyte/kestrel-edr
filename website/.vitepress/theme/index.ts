import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'
import Shot from './Shot.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    // <Shot name="console/overview" alt="..." /> picks the -dark / -light
    // screenshot that matches the site theme. <Shot src="img/diagrams/x.svg" />
    // shows a single image. Paths are resolved against the site base at
    // runtime, so an image that has not been added yet does not break the build.
    app.component('Shot', Shot)
  },
} satisfies Theme
