VERSION=$(make version)

perl -pi -e "s/static MIGRATION_TEST_VERSION: u32 = VERSION;/static MIGRATION_TEST_VERSION: u32 = ${VERSION};/" src/handlers/migrate_handler.rs
perl -pi -e 's/pub static VERSION: u32 = .*;/pub static VERSION: u32 = 0;/' src/version.rs
