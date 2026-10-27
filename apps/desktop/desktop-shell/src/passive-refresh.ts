export type PassiveRefreshBlockers = {
  addOpen: boolean;
  pickerOpen: boolean;
  addAccountOpen: boolean;
  vaultDialogOpen: boolean;
  vaultAccessOpen: boolean;
  nativeDialogBusy: boolean;
  editingControlFocused: boolean;
};

export function shouldBlockPassiveRefresh(state: PassiveRefreshBlockers): boolean {
  return state.addOpen || state.pickerOpen || state.addAccountOpen || state.vaultDialogOpen || state.vaultAccessOpen ||
    state.nativeDialogBusy || state.editingControlFocused;
}

export function shouldRunPeriodicPassiveRefresh(
  state: PassiveRefreshBlockers,
  waitingForAccountSetup: boolean
): boolean {
  return !shouldBlockPassiveRefresh({
    ...state,
    addAccountOpen: state.addAccountOpen && !waitingForAccountSetup
  });
}
