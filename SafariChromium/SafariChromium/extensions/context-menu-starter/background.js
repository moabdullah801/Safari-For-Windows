const MENU_ITEM_ID = 'context-menu-starter-action';

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: MENU_ITEM_ID,
      title: 'Run my custom action',
      contexts: ['all'],
    });
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== MENU_ITEM_ID) return;
  performCustomAction(info, tab);
});

function performCustomAction(info, tab) {
  // Customize this function with the action you want the menu item to perform.
  console.info('Custom context-menu action', {
    pageUrl: info.pageUrl,
    selectionText: info.selectionText,
    tabId: tab && tab.id,
  });
}