# fsblame as a Nix flake for x86_64-linux and aarch64-linux; Nix 2.18 or newer with the
# `nix-command` and `flakes` features:
#   nix run github:Arinerron/fsblame -- doctor
#   nix profile add github:Arinerron/fsblame   # before Nix 2.30: nix profile install
#   nix build                                  # ./result/bin/fsblame, man pages, completions
#   nix develop                                # cargo, clippy, rustfmt, clang, bpftool
#   nix flake check                            # build, unit tests, the NixOS module's units
#
# On NixOS, the module records changes from boot on, for `fsblame blame`:
#   imports = [ fsblame.nixosModules.default ];
#   services.fsblame.record = { enable = true; paths = [ "/etc" "/srv" ]; };
{
  description = "Which command changed this file? Live eBPF attribution of file changes to the full process lineage: argv, cwd, ancestors, systemd unit, container and build step.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # The tracekit submodule at the tag it pins: `github:` flake sources omit submodules,
    # `inputs.self.submodules` or not. The build always uses this copy. Bump the tag with the
    # submodule, then run `nix flake update tracekit`.
    tracekit = {
      url = "github:Arinerron/tracekit/v0.1.0";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      tracekit,
    }:
    let
      inherit (nixpkgs) lib;
      perSystem =
        f:
        lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (
          system:
          let
            pkgs = nixpkgs.legacyPackages.${system};
          in
          f {
            inherit system pkgs;
            # build.rs compiles the BPF objects with $CLANG and -Werror, which the cc wrapper's
            # host flags (--gcc-toolchain) fail.
            clang = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";
          }
        );
    in
    {
      packages = perSystem (
        { pkgs, clang, ... }:
        rec {
          default = fsblame;
          fsblame = pkgs.rustPlatform.buildRustPackage {
            pname = "fsblame";
            inherit ((lib.importTOML ./Cargo.toml).workspace.package) version;
            src = self;
            postUnpack = ''
              rm -rf "$sourceRoot/tracekit"
              cp -r ${tracekit} "$sourceRoot/tracekit"
            '';
            cargoLock.lockFile = ./Cargo.lock;

            env.CLANG = clang;
            nativeBuildInputs = [ pkgs.installShellFiles ];
            # xtask writes the man pages.
            cargoBuildFlags = [
              "--package"
              "fsblame"
              "--package"
              "xtask"
            ];
            # Tests always unwind: under the release profile (panic = "abort", fat LTO) they
            # would rebuild everything at full cost.
            checkType = "debug";
            # The recorder unit, not enabled (systemd ignores a profile's units; the NixOS
            # module below enables it). Its settings file is /etc/default/fsblame, as in
            # contrib/systemd/fsblame.default.
            postInstall = ''
              $out/bin/xtask man man
              rm $out/bin/xtask
              installManPage man/*.1
              installShellCompletion --cmd fsblame \
                --bash <($out/bin/fsblame completions bash) \
                --fish <($out/bin/fsblame completions fish) \
                --zsh <($out/bin/fsblame completions zsh)
              install -Dm644 contrib/systemd/fsblame-record.service -t $out/lib/systemd/system
              substituteInPlace $out/lib/systemd/system/fsblame-record.service \
                --replace-fail ExecStart=/usr/local/bin/fsblame ExecStart=$out/bin/fsblame
            '';

            meta = {
              description = "Attributes file changes to the commands that made them, from eBPF";
              homepage = "https://github.com/Arinerron/fsblame";
              license = lib.licenses.mit;
              mainProgram = "fsblame";
              platforms = lib.platforms.linux;
            };
          };
        }
      );

      apps = perSystem (
        { system, ... }:
        {
          default = {
            type = "app";
            program = lib.getExe self.packages.${system}.fsblame;
            meta.description = "Attributes file changes to the commands that made them, from eBPF";
          };
        }
      );

      # services.fsblame.record runs the package's fsblame-record.service (the same unit as
      # contrib/systemd, so the same capabilities and hardening) with its command line built
      # from these options instead of /etc/default/fsblame. The journal is /var/lib/fsblame,
      # where `sudo fsblame blame PATH` reads it.
      nixosModules.default =
        {
          config,
          lib,
          pkgs,
          utils,
          ...
        }:
        let
          cfg = config.services.fsblame.record;
        in
        {
          options.services.fsblame.record = {
            enable = lib.mkEnableOption "fsblame-record.service, which records which commands change the watched paths, for `fsblame blame`";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.fsblame;
              defaultText = lib.literalExpression "fsblame.packages.\${pkgs.stdenv.hostPlatform.system}.default";
              description = "The fsblame package; also added to environment.systemPackages.";
            };
            paths = lib.mkOption {
              type = lib.types.nonEmptyListOf lib.types.str;
              example = [
                "/etc"
                "/home/alice/.ssh"
              ];
              description = "Files and directories to record changes to; a directory includes its whole subtree.";
            };
            extraArgs = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              example = [
                "--exclude"
                "/etc/static"
                "--keep"
                "16"
              ];
              description = "Further `fsblame record` flags, see fsblame-record(1).";
            };
          };

          config = lib.mkIf cfg.enable {
            environment.systemPackages = [ cfg.package ];
            systemd.packages = [ cfg.package ];
            systemd.services.fsblame-record = {
              wantedBy = [ "multi-user.target" ];
              serviceConfig = {
                # Empty values reset the unit's settings file and command line.
                EnvironmentFile = "";
                ExecStart = [
                  ""
                  "${lib.getExe cfg.package} record --journal \${STATE_DIRECTORY} ${utils.escapeSystemdExecArgs (cfg.extraArgs ++ cfg.paths)}"
                ];
              };
            };
          };
        };

      checks = perSystem (
        { system, pkgs, ... }:
        {
          # The build, with the unit tests.
          fsblame = self.packages.${system}.fsblame;
          # The units a NixOS system with the module enabled gets (no VM: booting one needs
          # KVM): the package's unit, enabled, with the settings file and command line replaced.
          nixos-module =
            let
              fsblame = self.packages.${system}.fsblame;
              nixos = nixpkgs.lib.nixosSystem {
                modules = [
                  self.nixosModules.default
                  {
                    nixpkgs.hostPlatform = system;
                    boot.isContainer = true;
                    system.stateVersion = lib.trivial.release;
                    services.fsblame.record = {
                      enable = true;
                      paths = [ "/srv/watched dir" ];
                      extraArgs = [ "--summary" ];
                    };
                  }
                ];
              };
              units = nixos.config.environment.etc."systemd/system".source;
            in
            pkgs.runCommand "fsblame-nixos-module" { } ''
              unit=${units}/fsblame-record.service
              [ "$(readlink -f $unit)" = ${fsblame}/lib/systemd/system/fsblame-record.service ]
              [ -e ${units}/multi-user.target.wants/fsblame-record.service ]
              overrides=$unit.d/overrides.conf
              grep -Fx 'EnvironmentFile=' $overrides
              grep -Fx 'ExecStart=' $overrides
              grep -Fx 'ExecStart=${fsblame}/bin/fsblame record --journal ''${STATE_DIRECTORY} "--summary" "/srv/watched dir"' $overrides
              touch $out
            '';
        }
      );

      devShells = perSystem (
        { pkgs, clang, ... }:
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.cargo
              pkgs.rustc
              pkgs.clippy
              pkgs.rustfmt
              pkgs.bpftools
            ];
            CLANG = clang;
          };
        }
      );
    };
}
