/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shenyu.admin.service.configs;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.shenyu.admin.model.dto.AppAuthDTO;
import org.apache.shenyu.admin.model.result.ConfigImportResult;
import org.apache.shenyu.admin.model.vo.AppAuthVO;
import org.apache.shenyu.admin.service.AppAuthService;
import org.apache.shenyu.common.constant.ExportImportConstants;
import org.apache.shenyu.common.utils.GsonUtils;
import org.apache.shenyu.common.utils.JsonUtils;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;


@Component
public class AuthConfigsExportImportHandler implements ConfigsExportImportHandler {

    private final AppAuthService appAuthService;

    public AuthConfigsExportImportHandler(final AppAuthService appAuthService) {
        this.appAuthService = appAuthService;
    }

    @Override
    public ConfigsExportImportEnum configsEnum() {
        return ConfigsExportImportEnum.Auth;
    }

    @Override
    public Optional<String> configsExport(final String namespaceId) {
        List<AppAuthVO> authDataList = appAuthService.listAllDataByNamespace(namespaceId);
        if (CollectionUtils.isNotEmpty(authDataList)) {
            authDataList.forEach(appAuthVO -> appAuthVO.setNamespaceId(null));
            return Optional.of(JsonUtils.toJson(authDataList));
        }
        return Optional.empty();
    }

    @Override
    public void configsImport(final String namespaceId, final String data, final ConfigsImportContext context) {
        List<AppAuthDTO> authDataList = GsonUtils.getInstance().fromList(data, AppAuthDTO.class);
        ConfigImportResult configImportResult = appAuthService.importData(namespaceId, authDataList);
        context.getResult().put(ExportImportConstants.AUTH_IMPORT_SUCCESS_COUNT, configImportResult.getSuccessCount());
        if (StringUtils.isNotEmpty(configImportResult.getFailMessage())) {
            context.getResult().put(ExportImportConstants.AUTH_IMPORT_FAIL_MESSAGE, configImportResult.getFailMessage());
        }
    }
}
