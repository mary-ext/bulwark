<script lang="ts">
  import { toaster } from "../lib/toast.svelte";
  import Icon from "./Icon.svelte";
</script>

{#if toaster.msg}
  <div class="toast" class:error={toaster.error} role="status" aria-live="polite">
    <Icon name={toaster.error ? "block" : "check"} size={16} />
    <span>{toaster.msg}</span>
  </div>
{/if}

<style>
  .toast {
    position: fixed;
    bottom: var(--sp-4);
    left: 50%;
    transform: translateX(-50%);
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    max-width: min(92vw, 420px);
    background: var(--bg-elev);
    color: var(--text);
    border: 1px solid var(--border);
    border-left: 3px solid var(--good);
    padding: 0.7rem 1rem;
    border-radius: var(--radius);
    box-shadow: var(--shadow-lg);
    z-index: var(--z-toast);
    font-size: 0.875rem;
    animation: toast-in 0.2s ease;
  }
  .toast :global(svg) {
    color: var(--good);
    flex-shrink: 0;
  }
  .toast.error {
    border-left-color: var(--bad);
  }
  .toast.error :global(svg) {
    color: var(--bad);
  }
  @keyframes toast-in {
    from {
      opacity: 0;
      transform: translate(-50%, 8px);
    }
    to {
      opacity: 1;
      transform: translate(-50%, 0);
    }
  }
  @media (min-width: 769px) {
    .toast {
      left: auto;
      right: var(--sp-5);
      transform: none;
    }
    @keyframes toast-in {
      from {
        opacity: 0;
        transform: translateY(8px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
  }
</style>
