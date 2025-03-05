# import connector
# from typer.testing import CliRunner

# runner = CliRunner()


# def test_connector_run():
#     result = runner.invoke(
#         connector.connector.app, ["run", "-l", "INFO", "-j", '{"is_bool": true}']
#     )
#     print(result.stdout)
#     assert result.exit_code == 0
#     assert "hello world" in result.stdout
