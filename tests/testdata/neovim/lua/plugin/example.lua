local M = {}

function M.setup()
  vim.keymap.set("n", "<leader>e", vim.diagnostic.open_float)
end

return M
