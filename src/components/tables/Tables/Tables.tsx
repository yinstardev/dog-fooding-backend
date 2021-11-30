import React from 'react';
import { BasicTable } from '../BasicTable/BasicTable';
import { TreeTable } from '../TreeTable/TreeTable';
import { EditableTable } from '../EditableTable/EditableTable';
import { useTranslation } from 'react-i18next';
import * as S from './Tables.styles';

export const Tables: React.FC = () => {
  const { t } = useTranslation();
  return (
    <>
      <S.Title>{t('tables.tables')}</S.Title>
      <S.TablesWrapper>
        <S.Card title="Basic Table" padding="0 1.25rem">
          <BasicTable />
        </S.Card>
        <S.Card title="Tree Table" padding="0 1.25rem">
          <TreeTable />
        </S.Card>
        <S.Card title="Editable Table" padding="0 1.25rem">
          <EditableTable />
        </S.Card>
      </S.TablesWrapper>
    </>
  );
};