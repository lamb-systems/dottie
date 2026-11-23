package publicationstate

import "github.com/lamb-systems/dottie/internal/model"

func fileSetTestTargets() []model.Target {
	return []model.Target{{
		ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootXDGConfig, Path: "dotfiles", Kind: model.SelectionDirectory},
	}}
}
