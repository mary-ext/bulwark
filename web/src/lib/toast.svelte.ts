class Toaster {
  msg = $state<string | null>(null);
  error = $state(false);

  show(msg: string, error = false) {
    this.msg = msg;
    this.error = error;
    setTimeout(() => (this.msg = null), 3500);
  }
}

export const toaster = new Toaster();
