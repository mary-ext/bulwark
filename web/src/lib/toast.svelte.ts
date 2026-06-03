class Toaster {
  msg = $state<string | null>(null);
  error = $state(false);
  #timer: ReturnType<typeof setTimeout> | undefined;

  show(msg: string, error = false) {
    this.msg = msg;
    this.error = error;
    clearTimeout(this.#timer);
    this.#timer = setTimeout(() => (this.msg = null), 3500);
  }
}

export const toaster = new Toaster();
