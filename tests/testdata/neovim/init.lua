require("lazy").setup({
  { "example/plugin", config = function() require("plugin.example").setup() end },
})
