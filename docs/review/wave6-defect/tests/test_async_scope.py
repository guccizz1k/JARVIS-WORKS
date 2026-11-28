import asyncio
import pytest
import pytest_asyncio

@pytest_asyncio.fixture
async def loop_fixture():
    return asyncio.get_running_loop()

@pytest.mark.asyncio
async def test_function_loop(loop_fixture):
    assert loop_fixture is asyncio.get_running_loop()

@pytest_asyncio.fixture(scope='module', loop_scope='module')
async def module_fixture():
    return asyncio.get_running_loop()

@pytest.mark.asyncio(loop_scope='module')
async def test_explicit_module_loop(module_fixture):
    assert module_fixture is asyncio.get_running_loop()
